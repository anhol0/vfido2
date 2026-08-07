#include <algorithm>
#include <alloca.h>
#include <bits/chrono.h>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <limits>
#include <mutex>
#include <optional>
#include <span>
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
#include "uhid_report.hpp"

// PACKET STRUCTURE
// Channel ID (4 Bytes)
// CMD (1 Byte)
// Payload length (2 Bytes)
// Payload (N Bytes)
// Padding (zero everything until 64 bytes)

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

    struct IncomingTransaction {
        UHIDReport report;
        std::chrono::steady_clock::time_point deadline;
    };
}

void run(FIDODevice &device) {
#ifdef DEBUG
    // Showing
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-W#pragma-messages"
    #pragma message("Compiling with DEBUG mode ON")
    #pragma diagnostic pop
#endif
    std::unordered_set<uint32_t> allocated_cids;

    std::mutex completion_mutex;
    std::optional<TaskResult> completion;
    std::optional<ActiveTask> active;

    using Clock = std::chrono::steady_clock;
    constexpr auto MESSAGE_ASSEMBLY_TIMEOUT = std::chrono::seconds(3);
    constexpr std::size_t CTAPHID_MAX_PAYLOAD_SIZE = 7609;

    uint64_t next_generation = 1;
    std::jthread worker;

    pollfd device_poll{
        .fd = device.native_handle(),
        .events = POLLIN,
        .revents = 0
    };

    // Record incoming transaction and completed report
    std::optional<IncomingTransaction> incoming;
    while (true) {
        device_poll.revents = 0;

        // Timeout calculation
        int timeout = -1;
        if(active) {
            timeout = active->cancel_requested ? 20 :milliseconds_until(active->next_keepalive);
        }
        if(incoming) {
            const int assembly_timeout = milliseconds_until(incoming->deadline);
            if(timeout < 0 || assembly_timeout < timeout) {
                timeout = assembly_timeout;
            }
        }
        // End timeout calculation

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

        const auto now = Clock::now();
        if(incoming && now >= incoming->deadline) {
            const uint32_t timed_out_cid = incoming->report.cid;
            incoming.reset();
            send_packet(device, make_hid_error(timed_out_cid, HIDError::CTAP1_ERR_TIMEOUT));
        }

        if(device_poll.revents & POLLIN) {
            if(!device.get())
                continue;

            // If client sent data to the server, process it
            if (device.get_type() == UHID_OUTPUT) {
                std::optional<UHIDReport> completed;
                const std::vector<uint8_t> data = device.get_data();

                std::span<const uint8_t> frame = data;
                if(frame.size()  == 65 && frame[0] == 0) {
                    frame = frame.subspan(1);
                }
                if(frame.size() != 64) {
                    std::cerr << "Invalid HID request size\n";
                    continue;
                }

#ifdef DEBUG
                // Log the data in debug configuration
                printf("\x1b[1;31mGot data: \x1b[0m");
                for(int i = 1; i < frame.size(); i++) {
                    printf("%02x", frame[i]);
                }
                std::cout << "\n";
#endif

                uint32_t cid = (static_cast<uint32_t>(frame[0]) << 24) |
                               (static_cast<uint32_t>(frame[1]) << 16) |
                               (static_cast<uint32_t>(frame[2]) << 8 ) |
                               (static_cast<uint32_t>(frame[3]));

                // Check if the frame is initialization frame
                uint8_t is_init_packet = (frame[4] & MASK);

                // Handling of initialization and continuation packets
                // Can be performed synchronously
                // Parsing the frames that arrive from the authenticator and building one singular UHIDReport
                // It will be used later in creating responses
                if(is_init_packet) {
                    // Channel ID (4 bytes)

                    // Command (1 byte)
                    uint8_t cmd = frame[4] & 0x7F;

                    // Length of the nonce (2 bytes)
                    uint16_t length = ((uint16_t)frame[5] << 8) |
                                      ((uint16_t)frame[6]);

                    // If it is initialization packet is bigger then MAX_INIT_PAYLOAD_SIZE
                    if(length > CTAPHID_MAX_PAYLOAD_SIZE) {
                        send_packet(device, make_hid_error(cid, HIDError::CTAP1_ERR_INVALID_LENGTH));
                        continue;
                    }

                    // CTAPHID_INITs' and CTAPHID_CANCELs' payloads have to be
                    // Exactly 8 and 0 bytes respectively
                    if (cmd == CTAPHID_INIT && length != 8) {
                         send_packet(device,make_hid_error(cid,HIDError::CTAP1_ERR_INVALID_LENGTH));
                         continue;
                     }

                     if (cmd == CTAPHID_CANCEL && length != 0) {
                         send_packet(device,make_hid_error(cid,HIDError::CTAP1_ERR_INVALID_LENGTH));
                         continue;
                     }

                    // Cancel on a non-active CID should be ignored
                    if (cmd == CTAPHID_CANCEL && (!active || cid != active->cid)) {
                        continue;
                    }

                    if(active) {
                        const bool allowed_control_command =
                            cid == active->cid &&
                            (cmd == CTAPHID_CANCEL ||
                             cmd == CTAPHID_INIT);
                        if(!allowed_control_command) {
                            send_packet(device, make_hid_error(cid, HIDError::CTAP1_ERR_CHANNEL_BUSY));
                            continue;
                        }
                    }

                    // Different CID can't interrupt message assembly
                    if(incoming && cid != incoming->report.cid) {
                        send_packet(device, make_hid_error(cid, HIDError::CTAP1_ERR_CHANNEL_BUSY));
                        continue;
                    }

                    // Block packets that are being sent on uninitialized channels
                    const bool allocating_channel =
                        cid == CTAPHID_BROADCAST_CID &&
                        cmd == CTAPHID_INIT;

                    if(!allocating_channel && !allocated_cids.contains(cid)) {
                        send_packet(device, make_hid_error(cid, HIDError::CTAP1_ERR_INVALID_CHANNEL));
                        continue;
                    }

                    // Same CID INIT aborts incomplete message assembly
                    if(incoming && cid == incoming->report.cid && cmd == CTAPHID_INIT) {
                        incoming.reset();
                    } else if (incoming) {
                        const uint32_t interrupted_cid = incoming->report.cid;
                        incoming.reset();
                        send_packet(device, make_hid_error(interrupted_cid, HIDError::CTAP1_ERR_INVALID_SEQ));
                        continue;
                    }

                    UHIDReport next {};
                    next.cid = cid;
                    next.cmd = cmd;
                    next.len = length;

                    const std::size_t first_payload_size = std::min<std::size_t>(length, MAX_INIT_PAYLOAD_SIZE);
                    next.payload.insert(next.payload.end(), frame.begin()+7, frame.begin()+7+first_payload_size);

                    if(next.payload.size() == next.len) {
                        completed = std::move(next);
                    } else  {
                        incoming = IncomingTransaction{
                            .report = std::move(next),
                            .deadline = Clock::now() + MESSAGE_ASSEMBLY_TIMEOUT
                        };
                    }

                } else {
                    if(!incoming)
                        continue;

                    if(cid != incoming->report.cid)
                        continue;

                    UHIDReport &current = incoming->report;
                    const uint8_t sequence = frame[4];

                    if(sequence != current.seq) {
                        const uint32_t invalid_cid = current.cid;
                        incoming.reset();
                        send_packet(device, make_hid_error(invalid_cid, HIDError::CTAP1_ERR_INVALID_SEQ));
                        continue;
                    }

                    ++current.seq;

                    const std::size_t remaining = current.len - current.payload.size();
                    const std::size_t amount = std::min<std::size_t>(remaining, MAX_CONT_PAYLOAD_SIZE);
                    current.payload.insert(current.payload.end(), frame.begin() + 5, frame.begin() + 5 + amount);

                    if(current.payload.size() == current.len) {
                        completed = std::move(current);
                        incoming.reset();
                    }
                }
                // End UHID frame parsing

                // Building and sending responses for the requests
                // makeCredential and getAssertion requests are handled asynchronously on a separate thread
                // This is done to not block main thread from packet receiving and ability to send keep-alive packets
                // Cancel requests can arrive at a time of operation processing
                // Also parallel requests may arrive and senser will receive ERR_CHANNEL_BUSY error
                if(completed) {
                    UHIDReport request = std::move(*completed);
                    completed.reset();

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

                    // Handling initialization packets
                    if(request.cmd == CTAPHID_INIT) {

                        if(request.payload.empty()) {
                            send_packet(device, make_hid_error(request.cid, HIDError::CTAP1_ERR_INVALID_LENGTH));
                            continue;
                        }

                        // Blocking any other simultaneous requests
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

                    // Error handling for incoming packets
                    if (!allocated_cids.contains(request.cid)) {
                        send_packet(device, make_hid_error(request.cid,HIDError::CTAP1_ERR_INVALID_CHANNEL));
                        continue;
                    }

                    if (active) {
                         send_packet(device, make_hid_error(request.cid, HIDError::CTAP1_ERR_CHANNEL_BUSY));
                         continue;
                    }
                    // End error handling

                    // Echoing payload of the request in response
                    if(request.cmd == CTAPHID_PING) {
                        send_packet(device, handle_ping(request));
                        continue;
                    }

                    // Handling all the CBOR operations on a separahe thread
                    if(request.cmd == CTAPHID_CBOR) {
                        if(request.payload.empty()) {
                            send_packet(device, make_hid_error(request.cid, HIDError::CTAP1_ERR_INVALID_LENGTH));
                            continue;
                        }

                        if(active) {
                            send_packet(device, make_hid_error(request.cid, HIDError::CTAP1_ERR_CHANNEL_BUSY));
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

                    // If any other command arrives, it is invalid
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

        const auto keepalive_now = Clock::now();
        if(
            active &&
            keepalive_now >= active->next_keepalive &&
            !active->cancel_requested
        ){
            send_keepalive(
                device,
                active->cid,
                active->status
            );
            active->next_keepalive = keepalive_now + std::chrono::milliseconds(100);
        }
    }
}
