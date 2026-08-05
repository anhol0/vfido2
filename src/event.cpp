#include <alloca.h>
#include <bits/chrono.h>
#include <cerrno>
#include <cstdint>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <limits>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <stop_token>
#include <sys/poll.h>
#include <system_error>
#include <thread>
#include <unordered_set>

#include "event.hpp"
#include "cancellation.hpp"
#include "device.hpp"
#include "response.hpp"
#include "error.hpp"
#include "credentials/credential.hpp"
#include "uhid_report.hpp"

// --- PACKET STRUCTURE ---
// Channel ID (4 Bytes)
// CMD (1 Byte)
// Payload length (2 Bytes)
// Payload (N Bytes)
// Padding (zero everything until 64 bytes)

CredentialStore store;
FIDODevice device;

constexpr uint32_t CTAPHID_INVALID_CID   = 0x00000000;
constexpr uint32_t CTAPHID_BROADCAST_CID = 0xFFFFFFFF;

namespace {
    enum class KeepaliveStatus : uint8_t {
        processing = 1,
        up_neeeded = 2
    };

    struct ActiveTask {
        uint64_t generation;
        uint32_t cid;
        KeepaliveStatus status;
        std::chrono::steady_clock::time_point next_keepalive;
        bool cancel_requested = false;
        bool discard_result = false;
    };

    struct TaskResult {
        uint64_t generation;
        uint32_t cid;
        CTAPPacket packet;
    };

    int milliseconds_until(
        std::chrono::steady_clock::time_point deadline
    ) {
        using namespace std::chrono;
        const auto now = steady_clock::now();
        if(deadline <= now)
            return 0;

        const auto remaining = ceil<milliseconds>(deadline - now);
        const auto count = remaining.count();
        if(count > std::numeric_limits<int>::max())
            return std::numeric_limits<int>::max();

        return static_cast<int>(count);
    }

    void send_packet(FIDODevice& device, CTAPPacket packet)
     {
         auto frames = frame_packet(packet);

         for (auto& frame : frames) {
             if (!device.send(frame))
                 throw std::runtime_error("Failed to send UHID response");
         }
     }

    void send_keepalive(
        FIDODevice& device,
        uint32_t cid,
        KeepaliveStatus status
    ) {
        CTAPPacket packet;
        packet.cid = cid;
        packet.cmd = CTAPHID_KEEPALIVE | MASK;
        packet.payload = {static_cast<uint8_t>(status)};
        packet.len = static_cast<uint16_t>(packet.payload.size());

        send_packet(device, std::move(packet));
    }

    uint32_t allocate_cid(std::unordered_set<uint32_t>& allocated_cids) {
        uint32_t candidate;
        do
            arc4random_buf(&candidate, sizeof(candidate));
        while (
            candidate == CTAPHID_BROADCAST_CID ||
            candidate == CTAPHID_INVALID_CID ||
            allocated_cids.contains(candidate)
        );
        allocated_cids.insert(candidate);
        return candidate;
    }
}

void run(FIDODevice &device) {
#ifdef DEBUG
    #pragma message("Compiling with DEBUG mode ON - Using local config path")
#endif
    UHIDReport report;
    std::unordered_set<uint32_t> allocated_cids;

    std::mutex completion_mutex;
    std::optional<TaskResult> completion;
    std::optional<ActiveTask> active;

    uint64_t next_generation = 1;
    std::jthread worker;

    pollfd device_poll{
        .fd = device.native_handle(),
        .events = POLLIN,
        .revents = 0
    };

    store.init();
    while (true) {
        device_poll.revents = 0;

        const int timeout =
              !active ? -1 :
              active->cancel_requested ? 20 :
              milliseconds_until(active->next_keepalive);
        int poll_result;

        do {
            poll_result = poll(&device_poll, 1, timeout);
        } while (poll_result < 0 && errno == EINTR);

        if (poll_result < 0) {
            throw  std::system_error(errno, std::generic_category(), "Failed to poll UHID device");
        }

        if(device_poll.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            throw std::runtime_error("UHID polling failed");
        }

        if(device_poll.revents & POLLIN) {
            if(!device.get())
                continue;

            // If client sent data to the server, process it
            if (device.get_type() == UHID_OUTPUT) {

                std::vector<uint8_t> data = device.get_data();

                // Log the data in debug configuration
#ifdef DEBUG
                    printf("\x1b[1;31mGot data: \x1b[0m");
                    for(int i = 1; i < data.size(); i++) {
                        printf("%02x", data[i]);
                    }
                    std::cout << "\n";
#endif

                // Check if the frame is initialization frame
                uint8_t is_init_packet = (data[5] & 0x80);
                bool respd = false;

                // Handling of initialization and continuation packets
                // Can be performed synchronously
                if(is_init_packet) {
                    // Channel ID (4 bytes)
                    uint32_t cid = ((uint32_t)data[1] << 24) |
                                   ((uint32_t)data[2] << 16) |
                                   ((uint32_t)data[3] << 8 ) |
                                   ((uint32_t)data[4]);
                    // Command (1 byte)
                    uint8_t cmd = data[5] & 0x7F;
                    // Length of the nonce (2 bytes)
                    uint16_t length = ((uint16_t)data[6] << 8) |
                                      ((uint16_t)data[7]);

                    report.cid = cid;
                    report.cmd = cmd;
                    report.len = length;
                    report.payload.clear();

                    // If it is initialization packet and payload is bigger then MAX_INIT_PAYLOAD_SIZE
                    if(report.len > MAX_INIT_PAYLOAD_SIZE) {
                        for(int i = 0; i < MAX_INIT_PAYLOAD_SIZE; i++) {
                            report.payload.push_back(data[8+i]);
                        }
                        respd = false;
                    }
                    // If init packet is the only one in the packet sequence
                    else {
                        for(int i = 0; i < report.len; i++) {
                            report.payload.push_back(data[8+i]);
                        }
                        respd = true;
                    }
                } else {
                    uint32_t frame_cid = ((uint32_t)data[1] << 24) |
                                   ((uint32_t)data[2] << 16) |
                                   ((uint32_t)data[3] << 8 ) |
                                   ((uint32_t)data[4]);
                    if(frame_cid != report.cid || frame_cid == 0 ) {
                        continue;
                    }
                    uint8_t expected_seq = report.seq;
                    report.seq = data[5];
                    if(expected_seq != report.seq) {
                        std::cerr << "Continuation packets out of order\n";
                        send_packet(device, make_hid_error(report.cid, HIDError::CTAP1_ERR_INVALID_SEQ));
                        report.clear();
                        continue;
                    }
                    report.seq++;
                    // If continuation packet
                    for(int i = 0; i < MAX_CONT_PAYLOAD_SIZE; i++) {
                        report.payload.push_back(data[6+i]);
                        // If size of payload recieved = size of payload expected
                        // Break tf out
                        if(report.payload.size() >= report.len) {
                            respd = true;
                            break;
                        }
                    }
                    if(report.payload.size() > 7609) {
                        report.clear();
                        send_packet(device, make_hid_error(report.cid, HIDError::CTAP1_ERR_INVALID_LENGTH));
                        continue;
                    }
                }

                if(respd) {
                    UHIDReport request = std::move(report);
                    report.clear();

                    if(request.cmd == CTAPHID_INIT) {
                        if(request.payload.empty()) {
                            send_packet(device, make_hid_error(request.cid, HIDError::CTAP1_ERR_INVALID_LENGTH));
                            continue;
                        }
                        if(active && request.cid != active->cid) {
                            send_packet(device, make_hid_error(request.cid, HIDError::CTAP1_ERR_CHANNEL_BUSY));
                            continue;
                        }

                        uint32_t assigned_cid;

                        if(request.cid == CTAPHID_BROADCAST_CID) {
                            assigned_cid = allocate_cid(allocated_cids);
                        } else {
                            if(!allocated_cids.contains(request.cid)) {
                                send_packet(device, make_hid_error(request.cid, HIDError::CTAP1_ERR_INVALID_CHANNEL));
                                continue;
                            }
                            assigned_cid = request.cid;

                            if(active && active->cid == request.cid) {
                                active->cancel_requested = true;
                                active->discard_result = true;
                                worker.request_stop();
                            }
                        }
                        send_packet(device, handle_init(request, assigned_cid));
                        continue;
                    }

                    if(request.cmd == CTAPHID_CANCEL) {
                        if(active &&
                            active->cid == request.cid &&
                            !active->discard_result
                        ){
                            active->cancel_requested = true;
                            worker.request_stop();
                        }
                        continue;
                    }

                    if (!allocated_cids.contains(request.cid)) {
                        send_packet(device, make_hid_error(request.cid,HIDError::CTAP1_ERR_INVALID_CHANNEL));
                        continue;
                    }

                    if (active) {
                         send_packet(device, make_hid_error(request.cid, HIDError::CTAP1_ERR_CHANNEL_BUSY));
                         continue;
                     }

                    if(request.cmd == CTAPHID_PING) {
                        send_packet(device, handle_ping(request));
                        continue;
                    }

                    if(request.cmd == CTAPHID_CBOR) {
                        if(request.payload.empty()) {
                            auto packet = make_hid_error(request.cid, HIDError::CTAP1_ERR_INVALID_LENGTH);
                            send_packet(device, std::move(packet));
                            continue;
                        }

                        if(active) {
                            auto packet = make_hid_error(request.cid, HIDError::CTAP1_ERR_CHANNEL_BUSY);
                            send_packet(device, std::move(packet));
                            continue;
                        }

                        uint64_t generation = next_generation++;
                        active = ActiveTask {
                            .generation = generation,
                            .cid = request.cid,
                            .status = KeepaliveStatus::processing,
                            .next_keepalive =
                                std::chrono::steady_clock::now() +
                                std::chrono::milliseconds(100)
                        };

                        worker = std::jthread(
                            [
                                request = std::move(request),
                                generation,
                                &completion_mutex,
                                &completion
                            ]
                            (std::stop_token stop) mutable
                        {
                            TaskResult result {
                                .generation = generation,
                                .cid = request.cid
                            };
                            try {
                                result.packet = execute_ctap_request(std::move(request), stop);
                            } catch (const OperationCancelled&) {
                                result.packet = make_cbor_error(
                                    result.cid,
                                    CTAPError::CTAP2_ERR_KEEPALIVE_CANCEL
                                );
                            } catch (const std::exception &e) {
                                result.packet = make_cbor_error(
                                    result.cid,
                                    CTAPError::CTAP1_ERR_OTHER
                                );
                            }
                            std::lock_guard lock(completion_mutex);
                            completion = std::move(result);
                        });
                    }

                    else {
                        send_packet(device, make_hid_error(request.cid, HIDError::CTAP1_ERR_INVALID_COMMAND));
                        continue;
                    }
                }
            }
        }

        std::optional<TaskResult> ready;
        {
            std::lock_guard lock(completion_mutex);
            ready.swap(completion);
        }
        if(ready && active && ready->generation == active->generation) {
            if(worker.joinable())
                worker.join();

            if(!active->discard_result) {
                send_packet(device, std::move(ready->packet));
            }
            active.reset();
        }
        const auto now = std::chrono::steady_clock::now();
        if(
            active &&
            now >= active->next_keepalive &&
            !active->cancel_requested
        ){
            send_keepalive(
                device,
                active->cid,
                active->status
            );
            active->next_keepalive = now + std::chrono::milliseconds(100);
        }
    }
}
