#include "cancellable_process.hpp"

#include "cancellation.hpp"

#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <mutex>
#include <optional>
#include <spawn.h>
#include <stdexcept>
#include <system_error>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

extern char** environ;

namespace vfido::uv {
namespace {

class SpawnAttributes {
public:
    SpawnAttributes() {
        const int rc = posix_spawnattr_init(&attributes_);
        if(rc != 0)
            throw std::system_error(rc, std::generic_category(), "posix_spawnattr_init");
    }

    ~SpawnAttributes() {
        posix_spawnattr_destroy(&attributes_);
    }

    SpawnAttributes(const SpawnAttributes&) = delete;
    SpawnAttributes& operator=(const SpawnAttributes&) = delete;

    posix_spawnattr_t* get() noexcept {
        return &attributes_;
    }

private:
    posix_spawnattr_t attributes_{};
};

class SpawnFileActions {
public:
    SpawnFileActions() {
        int rc = posix_spawn_file_actions_init(&actions_);
        if(rc != 0)
            throw std::system_error(rc, std::generic_category(), "posix_spawn_file_actions_init");

        rc = posix_spawn_file_actions_addclosefrom_np(
            &actions_,
            STDERR_FILENO + 1
        );
        if(rc != 0) {
            posix_spawn_file_actions_destroy(&actions_);
            throw std::system_error(rc, std::generic_category(), "posix_spawn_file_actions_addclosefrom_np");
        }
    }

    ~SpawnFileActions() {
        posix_spawn_file_actions_destroy(&actions_);
    }

    SpawnFileActions(const SpawnFileActions&) = delete;
    SpawnFileActions& operator=(const SpawnFileActions&) = delete;

    posix_spawn_file_actions_t* get() noexcept {
        return &actions_;
    }

private:
    posix_spawn_file_actions_t actions_{};
};

class ChildProcess {
public:
    explicit ChildProcess(pid_t pid) noexcept : pid_(pid) {}

    ~ChildProcess() {
        terminate_and_reap();
    }

    ChildProcess(const ChildProcess&) = delete;
    ChildProcess& operator=(const ChildProcess&) = delete;

    std::optional<int> poll() {
        int status = 0;
        const pid_t result = waitpid(pid_, &status, WNOHANG);
        if(result == 0)
            return std::nullopt;
        if(result < 0) {
            if(errno == EINTR)
                return std::nullopt;
            throw std::system_error(errno, std::generic_category(), "waitpid");
        }

        pid_ = -1;
        if(WIFEXITED(status))
            return WEXITSTATUS(status);
        if(WIFSIGNALED(status))
            throw std::runtime_error("child process terminated by signal");
        throw std::runtime_error("child process returned an invalid status");
    }

    void terminate_and_reap() noexcept {
        if(pid_ <= 0)
            return;

        // The child is its own process-group leader. Terminate descendants too,
        // so a PAM module cannot leave a prompt or helper behind after cancel.
        static_cast<void>(kill(-pid_, SIGTERM));

        constexpr auto grace_period = std::chrono::milliseconds(100);
        constexpr auto poll_interval = std::chrono::milliseconds(5);
        const auto deadline = std::chrono::steady_clock::now() + grace_period;
        int status = 0;
        while(std::chrono::steady_clock::now() < deadline) {
            const pid_t result = waitpid(pid_, &status, WNOHANG);
            if(result == pid_ || (result < 0 && errno == ECHILD)) {
                pid_ = -1;
                return;
            }
            if(result < 0 && errno != EINTR)
                break;
            std::this_thread::sleep_for(poll_interval);
        }

        static_cast<void>(kill(-pid_, SIGKILL));
        while(waitpid(pid_, &status, 0) < 0 && errno == EINTR) {}
        pid_ = -1;
    }

private:
    pid_t pid_;
};

}

int run_cancellable_program(
    const std::string& path,
    const std::vector<std::string>& arguments,
    std::stop_token stop
) {
    cancellation_point(stop);
    if(path.empty())
        throw std::invalid_argument("child program path is empty");

    std::vector<char*> argv;
    argv.reserve(arguments.size() + 2);
    argv.push_back(const_cast<char*>(path.c_str()));
    for(const std::string& argument : arguments)
        argv.push_back(const_cast<char*>(argument.c_str()));
    argv.push_back(nullptr);

    SpawnAttributes attributes;
    SpawnFileActions file_actions;
    int rc = posix_spawnattr_setpgroup(attributes.get(), 0);
    if(rc != 0)
        throw std::system_error(rc, std::generic_category(), "posix_spawnattr_setpgroup");
    rc = posix_spawnattr_setflags(attributes.get(), POSIX_SPAWN_SETPGROUP);
    if(rc != 0)
        throw std::system_error(rc, std::generic_category(), "posix_spawnattr_setflags");

    pid_t pid = -1;
    rc = posix_spawn(
        &pid,
        path.c_str(),
        file_actions.get(),
        attributes.get(),
        argv.data(),
        environ
    );
    if(rc != 0)
        throw std::system_error(rc, std::generic_category(), "posix_spawn");

    ChildProcess child(pid);
    std::mutex wait_mutex;
    std::condition_variable wait_condition;
    std::stop_callback wake_on_cancel(stop, [&wait_condition] {
        wait_condition.notify_all();
    });
    std::unique_lock wait_lock(wait_mutex);

    while(true) {
        if(stop.stop_requested()) {
            child.terminate_and_reap();
            throw OperationCancelled{};
        }
        if(const auto status = child.poll())
            return *status;

        wait_condition.wait_for(
            wait_lock,
            std::chrono::milliseconds(20),
            [stop] { return stop.stop_requested(); }
        );
    }
}

}
