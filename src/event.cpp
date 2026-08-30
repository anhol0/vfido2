#include <cerrno>
#include <cstdint>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <limits>
#include <memory>
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
#include "frame_processor.hpp"
#include "keepalive.hpp"
#include "uhid_report.hpp"

// PACKET STRUCTURE
// Channel ID (4 Bytes)
// CMD (1 Byte)
// Payload length (2 Bytes)
// Payload (N Bytes)
// Padding (zero everything until 64 bytes)

namespace {
    struct ActiveTask {
        uint64_t generation;
        uint32_t cid;
        std::shared_ptr<KeepaliveState> keepalive;
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

void run(
    FIDODevice& device,
    CredentialStore& store,
    CredentialKeyProvider& key_provider
) {
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

    uint64_t next_generation = 1;
    std::jthread worker;

    pollfd device_poll{
        .fd = device.native_handle(),
        .events = POLLIN,
        .revents = 0
    };

    CTAPHIDFrameProcessor frame_processor;
    while (true) {
        device_poll.revents = 0;

        // Timeout calculation
        int timeout = -1;
        if(active) {
            timeout = active->cancel_requested ? 20 :milliseconds_until(active->next_keepalive);
        }
        if(const auto deadline = frame_processor.deadline()) {
            const int assembly_timeout = milliseconds_until(*deadline);
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
        if(const auto timeout_error = frame_processor.expire(now)) {
            send_packet(
                device,
                make_hid_error(timeout_error->cid, timeout_error->error)
            );
        }

        if(device_poll.revents & POLLIN) {
            if(!device.get())
                continue;

            // If client sent data to the server, process it
            if (device.get_type() == UHID_OUTPUT) {
                const std::vector<uint8_t> data = device.get_data();

#ifdef DEBUG
                // Log the data in debug configuration
                printf("\x1b[1;31mGot data: \x1b[0m");
                for(const uint8_t byte : data) {
                    printf("%02x", byte);
                }
                std::cout << "\n";
#endif

                const std::optional<uint32_t> active_cid = active
                    ? std::optional<uint32_t>{active->cid}
                    : std::nullopt;
                FrameProcessingResult frame_result = frame_processor.process(
                    data,
                    active_cid,
                    allocated_cids,
                    Clock::now()
                );

                if(auto* error = std::get_if<FrameProcessingError>(&frame_result)) {
                    send_packet(device, make_hid_error(error->cid, error->error));
                    continue;
                }

                // Building and sending responses for the requests
                // makeCredential and getAssertion requests are handled asynchronously on a separate thread
                // This is done to not block main thread from packet receiving and ability to send keep-alive packets
                // Cancel requests can arrive at a time of operation processing
                // Also parallel requests may arrive and senser will receive ERR_CHANNEL_BUSY error
                if(auto* completed = std::get_if<UHIDReport>(&frame_result)) {
                    UHIDReport request = std::move(*completed);

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
                        auto keepalive = std::make_shared<KeepaliveState>();
                        active = ActiveTask {
                            .generation = generation,
                            .cid = request.cid,
                            .keepalive = keepalive,
                            .next_keepalive =
                                std::chrono::steady_clock::now() +
                                std::chrono::milliseconds(100)
                        };

                        worker = std::jthread(
                            [
                                request = std::move(request),
                                generation,
                                &completion_mutex,
                                &completion,
                                &store,
                                &key_provider,
                                keepalive
                            ]
                            (std::stop_token stop) mutable
                        {
                            TaskResult result {
                                .generation = generation,
                                .cid = request.cid
                            };
                            try {
                                result.packet = execute_ctap_request(
                                    std::move(request),
                                    stop,
                                    store,
                                    key_provider,
                                    *keepalive
                                );
                            } catch (const OperationCancelled &e) {
                                std::cout << "Exception: " <<  e.what() << std::endl;
                                result.packet = make_cbor_error(
                                    result.cid,
                                    CTAPError::CTAP2_ERR_KEEPALIVE_CANCEL
                                );
                            } catch (const UserActionTimedOut&) {
                                result.packet = make_cbor_error(
                                    result.cid,
                                    CTAPError::CTAP2_ERR_USER_ACTION_TIMEOUT
                                );
                            } catch (const std::exception &e) {
                                std::cout << "Exception: " << e.what() << std::endl;
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
                active->keepalive->get()
            );
            active->next_keepalive = keepalive_now + std::chrono::milliseconds(100);
        }
    }
}
