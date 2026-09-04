#include "cancellable_process.hpp"

#include "cancellation.hpp"
#include "auth_handler_status.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <fcntl.h>
#include <mutex>
#include <optional>
#include <spawn.h>
#include <stdexcept>
#include <system_error>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

extern char** environ;

namespace vauth::uv {
namespace {

class UniqueFd {
public:
    UniqueFd() = default;
    explicit UniqueFd(int fd) noexcept : fd_(fd) {}

    ~UniqueFd() {
        if(fd_ >= 0)
            static_cast<void>(close(fd_));
    }

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    UniqueFd(UniqueFd&& other) noexcept
        : fd_(std::exchange(other.fd_, -1)) {}

    UniqueFd& operator=(UniqueFd&& other) noexcept {
        if(this != &other) {
            if(fd_ >= 0)
                static_cast<void>(close(fd_));
            fd_ = std::exchange(other.fd_, -1);
        }
        return *this;
    }

    [[nodiscard]] int get() const noexcept {
        return fd_;
    }

    void reset(int fd = -1) noexcept {
        UniqueFd replacement(fd);
        *this = std::move(replacement);
    }

private:
    int fd_ = -1;
};

struct Pipe {
    UniqueFd read;
    UniqueFd write;
};

Pipe make_pipe(int flags, const char* operation) {
    std::array<int, 2> descriptors{};
    if(pipe2(descriptors.data(), flags) != 0) {
        throw std::system_error(
            errno,
            std::generic_category(),
            operation
        );
    }

    return {
        .read = UniqueFd(descriptors[0]),
        .write = UniqueFd(descriptors[1])
    };
}

void move_above_auth_descriptors(UniqueFd& descriptor) {
    if(
        descriptor.get() == AUTH_HANDLER_STATUS_FD ||
        descriptor.get() == AUTH_HANDLER_RESPONSE_FD
    ) {
        const int duplicate = fcntl(
            descriptor.get(),
            F_DUPFD_CLOEXEC,
            AUTH_HANDLER_RESPONSE_FD + 1
        );
        if(duplicate < 0) {
            throw std::system_error(
                errno,
                std::generic_category(),
                "duplicate authentication pipe descriptor"
            );
        }
        descriptor.reset(duplicate);
    }
}

void write_password(int fd, std::span<const uint8_t> password) {
    std::size_t written = 0;
    while(written < password.size()) {
        const ssize_t count = write(
            fd,
            password.data() + written,
            password.size() - written
        );
        if(count > 0) {
            written += static_cast<std::size_t>(count);
            continue;
        }
        if(count < 0 && errno == EINTR)
            continue;
        throw std::system_error(
            count < 0 ? errno : EIO,
            std::generic_category(),
            "write authentication password"
        );
    }
}

void drain_statuses(
    int fd,
    const std::function<void(uint8_t)>& callback
) {
    if(fd < 0 || !callback)
        return;

    std::array<uint8_t, 64> statuses{};
    while(true) {
        const ssize_t count = read(fd, statuses.data(), statuses.size());
        if(count > 0) {
            for(ssize_t index = 0; index < count; ++index)
                callback(statuses[static_cast<std::size_t>(index)]);
            continue;
        }
        if(count == 0 || (errno == EAGAIN || errno == EWOULDBLOCK))
            return;
        if(errno == EINTR)
            continue;
        throw std::system_error(
            errno,
            std::generic_category(),
            "read authentication status"
        );
    }
}

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
    SpawnFileActions(int status_write_fd, int response_read_fd) {
        int rc = posix_spawn_file_actions_init(&actions_);
        if(rc != 0)
            throw std::system_error(rc, std::generic_category(), "posix_spawn_file_actions_init");

        if(status_write_fd >= 0) {
            rc = posix_spawn_file_actions_adddup2(
                &actions_,
                status_write_fd,
                AUTH_HANDLER_STATUS_FD
            );
            if(rc != 0) {
                posix_spawn_file_actions_destroy(&actions_);
                throw std::system_error(
                    rc,
                    std::generic_category(),
                    "posix_spawn_file_actions_adddup2"
                );
            }
        }

        if(response_read_fd >= 0) {
            rc = posix_spawn_file_actions_adddup2(
                &actions_,
                response_read_fd,
                AUTH_HANDLER_RESPONSE_FD
            );
            if(rc != 0) {
                posix_spawn_file_actions_destroy(&actions_);
                throw std::system_error(
                    rc,
                    std::generic_category(),
                    "posix_spawn_file_actions_adddup2"
                );
            }
        }

        int close_from = STDERR_FILENO + 1;
        if(status_write_fd >= 0)
            close_from = AUTH_HANDLER_STATUS_FD + 1;
        if(response_read_fd >= 0)
            close_from = AUTH_HANDLER_RESPONSE_FD + 1;
        rc = posix_spawn_file_actions_addclosefrom_np(
            &actions_,
            close_from
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
    std::stop_token stop,
    std::chrono::steady_clock::duration timeout,
    const std::function<void(uint8_t)>& status_callback,
    const std::function<bool()>& cancellation_requested,
    const std::function<SensitiveBytes()>& password_callback
) {
    cancellation_point(stop);
    if(cancellation_requested && cancellation_requested())
        throw UserInteractionCancelled{};
    if(path.empty())
        throw std::invalid_argument("child program path is empty");
    if(timeout <= std::chrono::steady_clock::duration::zero())
        throw std::invalid_argument("child program timeout must be positive");

    const auto deadline = std::chrono::steady_clock::now() + timeout;

    std::vector<char*> argv;
    argv.reserve(arguments.size() + 2);
    argv.push_back(const_cast<char*>(path.c_str()));
    for(const std::string& argument : arguments)
        argv.push_back(const_cast<char*>(argument.c_str()));
    argv.push_back(nullptr);

    std::optional<Pipe> status_pipe;
    if(status_callback || password_callback) {
        status_pipe.emplace(make_pipe(
            O_CLOEXEC | O_NONBLOCK,
            "pipe2 authentication status"
        ));
        move_above_auth_descriptors(status_pipe->write);
    }

    std::optional<Pipe> response_pipe;
    if(password_callback) {
        response_pipe.emplace(make_pipe(
            O_CLOEXEC,
            "pipe2 authentication response"
        ));
        move_above_auth_descriptors(response_pipe->read);
    }

    SpawnAttributes attributes;
    SpawnFileActions file_actions(
        status_pipe ? status_pipe->write.get() : -1,
        response_pipe ? response_pipe->read.get() : -1
    );
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

    if(status_pipe)
        status_pipe->write.reset();
    if(response_pipe)
        response_pipe->read.reset();

    ChildProcess child(pid);
    std::mutex wait_mutex;
    std::condition_variable wait_condition;
    std::stop_callback wake_on_cancel(stop, [&wait_condition] {
        wait_condition.notify_all();
    });
    std::unique_lock wait_lock(wait_mutex);

    while(true) {
        if(status_pipe) {
            drain_statuses(status_pipe->read.get(), [&](uint8_t status) {
                if(status_callback)
                    status_callback(status);
                if(
                    status == static_cast<uint8_t>(
                        AuthHandlerStatus::password_required
                    ) &&
                    password_callback
                ) {
                    if(!response_pipe || response_pipe->write.get() < 0) {
                        throw std::runtime_error(
                            "Authentication password was requested twice"
                        );
                    }
                    auto password = password_callback();
                    write_password(
                        response_pipe->write.get(),
                        password.bytes()
                    );
                    response_pipe->write.reset();
                }
            });
        }
        if(stop.stop_requested()) {
            child.terminate_and_reap();
            throw OperationCancelled{};
        }
        if(cancellation_requested && cancellation_requested()) {
            child.terminate_and_reap();
            throw UserInteractionCancelled{};
        }
        if(const auto status = child.poll()) {
            if(status_pipe) {
                drain_statuses(status_pipe->read.get(), [&](uint8_t status) {
                    if(status_callback)
                        status_callback(status);
                });
            }
            return *status;
        }

        const auto now = std::chrono::steady_clock::now();
        if(now >= deadline) {
            child.terminate_and_reap();
            throw UserActionTimedOut{};
        }

        wait_condition.wait_until(
            wait_lock,
            std::min(
                deadline,
                now + std::chrono::milliseconds(20)
            ),
            [stop] { return stop.stop_requested(); }
        );
    }
}

}
