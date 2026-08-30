#include "cancellation.hpp"
#include "keepalive.hpp"
#include "uv/src/cancellable_process.hpp"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <stop_token>
#include <stdexcept>
#include <string>
#include <thread>
#include <unistd.h>

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
    CHECK(vfido::uv::run_cancellable_program(
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
            static_cast<void>(vfido::uv::run_cancellable_program(
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
        static_cast<void>(vfido::uv::run_cancellable_program(
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

    const std::string executable = std::filesystem::canonical(argv[0]);
    const bool success =
        test_exit_status(executable) &&
        test_cancellation_interrupts_child(executable) &&
        test_timeout_interrupts_child(executable) &&
        test_user_action_keepalive_scope();
    if(success)
        std::cout << "4/4 UV process tests passed\n";
    return success ? 0 : 1;
}
