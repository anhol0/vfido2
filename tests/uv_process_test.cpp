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
#include <cstdlib>
#include <filesystem>
#include <fcntl.h>
#include <iostream>
#include <signal.h>
#include <stop_token>
#include <stdexcept>
#include <string>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {

volatile sig_atomic_t graceful_cancel_received = 0;

void record_graceful_cancel(int) noexcept {
    graceful_cancel_received = 1;
}

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

bool test_cancellation_uses_graceful_signal(const std::string& executable) {
    std::string marker_template = "/tmp/vauth-cancel-test-XXXXXX";
    const int marker_fd = mkstemp(marker_template.data());
    CHECK(marker_fd >= 0);
    close(marker_fd);

    std::atomic<bool> ready = false;
    std::atomic<bool> cancelled = false;
    std::atomic<bool> unexpected_error = false;
    std::jthread worker([&](std::stop_token stop) {
        try {
            static_cast<void>(vauth::uv::run_cancellable_program(
                executable,
                {"--child-graceful-cancel", marker_template},
                stop,
                std::chrono::seconds(5),
                [&ready](uint8_t) {
                    ready = true;
                }
            ));
        } catch(const OperationCancelled&) {
            cancelled = true;
        } catch(...) {
            unexpected_error = true;
        }
    });

    const auto ready_deadline = std::chrono::steady_clock::now() +
        std::chrono::seconds(1);
    while(!ready && std::chrono::steady_clock::now() < ready_deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    CHECK(ready);
    worker.request_stop();
    worker.join();

    const int result_fd = open(marker_template.c_str(), O_RDONLY | O_CLOEXEC);
    uint8_t marker = 0;
    const bool marked =
        result_fd >= 0 && read(result_fd, &marker, sizeof(marker)) == 1;
    if(result_fd >= 0)
        close(result_fd);
    static_cast<void>(unlink(marker_template.c_str()));

    CHECK(cancelled);
    CHECK(!unexpected_error);
    CHECK(marked);
    CHECK(marker == 1);
    return true;
}

bool test_parent_death_terminates_child() {
    int previous_subreaper = 0;
    CHECK(prctl(PR_GET_CHILD_SUBREAPER, &previous_subreaper) == 0);
    CHECK(prctl(PR_SET_CHILD_SUBREAPER, 1) == 0);

    std::array<int, 2> ready_pipe{};
    std::array<int, 2> report_pipe{};
    if(pipe2(ready_pipe.data(), O_CLOEXEC) != 0) {
        static_cast<void>(prctl(
            PR_SET_CHILD_SUBREAPER,
            previous_subreaper
        ));
        return false;
    }
    if(pipe2(report_pipe.data(), O_CLOEXEC) != 0) {
        close(ready_pipe[0]);
        close(ready_pipe[1]);
        static_cast<void>(prctl(
            PR_SET_CHILD_SUBREAPER,
            previous_subreaper
        ));
        return false;
    }

    const pid_t supervisor = fork();
    if(supervisor == 0) {
        close(report_pipe[0]);
        const pid_t watched_child = fork();
        if(watched_child == 0) {
            close(ready_pipe[0]);
            close(report_pipe[1]);
            try {
                vauth::uv::arm_parent_death_signal(getppid());
                const uint8_t ready = 1;
                if(write(ready_pipe[1], &ready, sizeof(ready)) != 1)
                    _exit(2);
                while(true)
                    pause();
            } catch(...) {
                _exit(3);
            }
        }
        close(ready_pipe[1]);
        uint8_t ready = 0;
        if(
            watched_child <= 0 ||
            read(ready_pipe[0], &ready, sizeof(ready)) != 1 ||
            ready != 1 ||
            write(
                report_pipe[1],
                &watched_child,
                sizeof(watched_child)
            ) != static_cast<ssize_t>(sizeof(watched_child))
        ) {
            if(watched_child > 0)
                static_cast<void>(kill(watched_child, SIGKILL));
            _exit(4);
        }
        _exit(0);
    }

    close(ready_pipe[0]);
    close(ready_pipe[1]);
    close(report_pipe[1]);

    pid_t watched_child = -1;
    const bool reported =
        supervisor > 0 &&
        read(
            report_pipe[0],
            &watched_child,
            sizeof(watched_child)
        ) == static_cast<ssize_t>(sizeof(watched_child));
    close(report_pipe[0]);

    int supervisor_status = 0;
    const bool supervisor_reaped =
        supervisor > 0 &&
        waitpid(supervisor, &supervisor_status, 0) == supervisor;

    bool child_reaped = false;
    int child_status = 0;
    if(reported && watched_child > 0) {
        const auto deadline = std::chrono::steady_clock::now() +
            std::chrono::seconds(1);
        while(std::chrono::steady_clock::now() < deadline) {
            const pid_t result = waitpid(watched_child, &child_status, WNOHANG);
            if(result == watched_child) {
                child_reaped = true;
                break;
            }
            if(result < 0 && errno != EINTR)
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        if(!child_reaped) {
            static_cast<void>(kill(watched_child, SIGKILL));
            while(waitpid(watched_child, &child_status, 0) < 0 && errno == EINTR) {
            }
        }
    }

    static_cast<void>(prctl(
        PR_SET_CHILD_SUBREAPER,
        previous_subreaper
    ));

    CHECK(reported);
    CHECK(supervisor_reaped);
    CHECK(WIFEXITED(supervisor_status));
    CHECK(WEXITSTATUS(supervisor_status) == 0);
    CHECK(child_reaped);
    CHECK(WIFSIGNALED(child_status));
    CHECK(WTERMSIG(child_status) == SIGINT);
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
    if(argc == 3 && std::string(argv[1]) == "--child-graceful-cancel") {
        struct sigaction interrupt_action{};
        interrupt_action.sa_handler = record_graceful_cancel;
        sigemptyset(&interrupt_action.sa_mask);
        if(sigaction(SIGINT, &interrupt_action, nullptr) != 0)
            return 1;
        struct sigaction term_action{};
        term_action.sa_handler = SIG_IGN;
        sigemptyset(&term_action.sa_mask);
        if(sigaction(SIGTERM, &term_action, nullptr) != 0)
            return 1;

        const uint8_t ready = static_cast<uint8_t>(
            vauth::uv::AuthHandlerStatus::fingerprint_required
        );
        if(
            write(
                vauth::uv::AUTH_HANDLER_STATUS_FD,
                &ready,
                sizeof(ready)
            ) != 1
        ) {
            return 1;
        }
        while(!graceful_cancel_received)
            pause();

        const int fd = open(
            argv[2],
            O_WRONLY | O_TRUNC | O_CLOEXEC
        );
        const uint8_t marker = 1;
        const bool written =
            fd >= 0 && write(fd, &marker, sizeof(marker)) == 1;
        if(fd >= 0)
            close(fd);
        return written ? 0 : 1;
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
    runner.run("test_cancellation_uses_graceful_signal", [&] {
        return test_cancellation_uses_graceful_signal(executable);
    });
    runner.run(
        "test_parent_death_terminates_child",
        test_parent_death_terminates_child
    );
    runner.run(
        "test_user_action_keepalive_scope",
        test_user_action_keepalive_scope
    );
    return runner.finish();
}
