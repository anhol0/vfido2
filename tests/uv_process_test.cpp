#include "cancellation.hpp"
#include "keepalive.hpp"
#include "test_runner.hpp"
#include "uv/src/auth_handler_status.hpp"
#include "uv/src/cancellable_process.hpp"

#include <algorithm>
#include <atomic>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <stop_token>
#include <stdexcept>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {

#define CHECK(condition) do { \
    if(!(condition)) { \
        std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ \
                  << ": " #condition "\n"; \
        return false; \
    } \
} while(false)

bool test_exit_status(const std::string& executable) {
    std::stop_source stop;
    CHECK(vauth::uv::run_cancellable_program(
        executable,
        {"--child-exit"},
        stop.get_token(),
        std::chrono::seconds(1)
    ) == 17);
    return true;
}

bool test_cancellation_interrupts_child(const std::string& executable) {
    std::atomic<bool> cancelled = false;
    std::atomic<bool> unexpected_error = false;
    const auto started = std::chrono::steady_clock::now();

    std::jthread worker([&](std::stop_token stop) {
        try {
            static_cast<void>(vauth::uv::run_cancellable_program(
                executable,
                {"--child-wait"},
                stop,
                std::chrono::seconds(5)
            ));
        } catch(const OperationCancelled&) {
            cancelled = true;
        } catch(...) {
            unexpected_error = true;
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    worker.request_stop();
    worker.join();

    const auto elapsed = std::chrono::steady_clock::now() - started;
    CHECK(cancelled);
    CHECK(!unexpected_error);
    CHECK(elapsed < std::chrono::seconds(1));
    return true;
}

bool test_timeout_interrupts_child(const std::string& executable) {
    std::stop_source stop;
    bool timed_out = false;
    bool unexpected_error = false;
    const auto started = std::chrono::steady_clock::now();

    try {
        static_cast<void>(vauth::uv::run_cancellable_program(
            executable,
            {"--child-wait"},
            stop.get_token(),
            std::chrono::milliseconds(50)
        ));
    } catch(const UserActionTimedOut&) {
        timed_out = true;
    } catch(...) {
        unexpected_error = true;
    }

    const auto elapsed = std::chrono::steady_clock::now() - started;
    CHECK(timed_out);
    CHECK(!unexpected_error);
    CHECK(elapsed < std::chrono::seconds(1));
    return true;
}

bool test_child_status_events(const std::string& executable) {
    std::stop_source stop;
    std::vector<uint8_t> received;
    CHECK(vauth::uv::run_cancellable_program(
        executable,
        {"--child-status"},
        stop.get_token(),
        std::chrono::seconds(1),
        [&received](uint8_t status) {
            received.push_back(status);
        }
    ) == 0);

    const std::vector<uint8_t> expected{
        static_cast<uint8_t>(
            vauth::uv::AuthHandlerStatus::fingerprint_required
        ),
        static_cast<uint8_t>(
            vauth::uv::AuthHandlerStatus::fingerprint_failed
        ),
        static_cast<uint8_t>(
            vauth::uv::AuthHandlerStatus::password_required
        )
    };
    CHECK(received == expected);
    return true;
}

bool test_password_delivery(const std::string& executable) {
    std::stop_source stop;
    std::size_t password_prompts = 0;
    CHECK(vauth::uv::run_cancellable_program(
        executable,
        {"--child-password"},
        stop.get_token(),
        std::chrono::seconds(1),
        [&password_prompts](uint8_t status) {
            if(
                status == static_cast<uint8_t>(
                    vauth::uv::AuthHandlerStatus::password_required
                )
            ) {
                ++password_prompts;
            }
        },
        {},
        [] {
            constexpr std::array<uint8_t, 6> password{
                's', 'e', 'c', 'r', 'e', 't'
            };
            vauth::uv::SensitiveBytes result(password.size());
            std::copy(
                password.begin(),
                password.end(),
                result.writable_bytes().begin()
            );
            return result;
        }
    ) == 0);
    CHECK(password_prompts == 1);
    return true;
}

bool test_external_cancellation_interrupts_child(
    const std::string& executable
) {
    std::atomic<bool> cancellation_requested = false;
    std::atomic<bool> cancelled = false;
    std::atomic<bool> unexpected_error = false;
    const auto started = std::chrono::steady_clock::now();

    std::jthread worker([&] {
        try {
            std::stop_source stop;
            static_cast<void>(vauth::uv::run_cancellable_program(
                executable,
                {"--child-wait"},
                stop.get_token(),
                std::chrono::seconds(5),
                {},
                [&cancellation_requested] {
                    return cancellation_requested.load();
                }
            ));
        } catch(const UserInteractionCancelled&) {
            cancelled = true;
        } catch(...) {
            unexpected_error = true;
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    cancellation_requested = true;
    worker.join();

    CHECK(cancelled);
    CHECK(!unexpected_error);
    CHECK(
        std::chrono::steady_clock::now() - started <
        std::chrono::seconds(1)
    );
    return true;
}

bool test_user_action_keepalive_scope() {
    KeepaliveState keepalive;
    CHECK(keepalive.get() == KeepaliveStatus::processing);
    {
        UserActionKeepaliveGuard waiting_for_user(keepalive);
        CHECK(keepalive.get() == KeepaliveStatus::up_needed);
    }
    CHECK(keepalive.get() == KeepaliveStatus::processing);

    try {
        UserActionKeepaliveGuard waiting_for_user(keepalive);
        throw std::runtime_error("test exception");
    } catch(const std::runtime_error&) {
    }
    CHECK(keepalive.get() == KeepaliveStatus::processing);
    return true;
}

}

int main(int argc, char** argv) {
    if(argc == 2 && std::string(argv[1]) == "--child-exit")
        return 17;
    if(argc == 2 && std::string(argv[1]) == "--child-wait") {
        while(true)
            pause();
    }
    if(argc == 2 && std::string(argv[1]) == "--child-status") {
        const std::array<uint8_t, 3> statuses{
            static_cast<uint8_t>(
                vauth::uv::AuthHandlerStatus::fingerprint_required
            ),
            static_cast<uint8_t>(
                vauth::uv::AuthHandlerStatus::fingerprint_failed
            ),
            static_cast<uint8_t>(
                vauth::uv::AuthHandlerStatus::password_required
            )
        };
        return write(
            vauth::uv::AUTH_HANDLER_STATUS_FD,
            statuses.data(),
            statuses.size()
        ) == static_cast<ssize_t>(statuses.size()) ? 0 : 1;
    }
    if(argc == 2 && std::string(argv[1]) == "--child-password") {
        const uint8_t status = static_cast<uint8_t>(
            vauth::uv::AuthHandlerStatus::password_required
        );
        if(
            write(
                vauth::uv::AUTH_HANDLER_STATUS_FD,
                &status,
                sizeof(status)
            ) != static_cast<ssize_t>(sizeof(status))
        ) {
            return 1;
        }

        std::array<uint8_t, 7> password{};
        std::size_t used = 0;
        while(used < password.size()) {
            const ssize_t count = read(
                vauth::uv::AUTH_HANDLER_RESPONSE_FD,
                password.data() + used,
                password.size() - used
            );
            if(count > 0) {
                used += static_cast<std::size_t>(count);
                continue;
            }
            if(count == 0)
                break;
            if(errno == EINTR)
                continue;
            return 1;
        }
        constexpr std::array<uint8_t, 6> expected{
            's', 'e', 'c', 'r', 'e', 't'
        };
        return
            used == expected.size() &&
            std::equal(expected.begin(), expected.end(), password.begin())
                ? 0
                : 1;
    }

    const std::string executable = std::filesystem::canonical(argv[0]);
    test_support::Runner runner;
    runner.run("test_exit_status", [&] {
        return test_exit_status(executable);
    });
    runner.run("test_cancellation_interrupts_child", [&] {
        return test_cancellation_interrupts_child(executable);
    });
    runner.run("test_timeout_interrupts_child", [&] {
        return test_timeout_interrupts_child(executable);
    });
    runner.run("test_child_status_events", [&] {
        return test_child_status_events(executable);
    });
    runner.run("test_password_delivery", [&] {
        return test_password_delivery(executable);
    });
    runner.run("test_external_cancellation_interrupts_child", [&] {
        return test_external_cancellation_interrupts_child(executable);
    });
    runner.run(
        "test_user_action_keepalive_scope",
        test_user_action_keepalive_scope
    );
    return runner.finish();
}
