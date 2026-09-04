#include "dbus/constants.hpp"

#include <sdbus-c++/sdbus-c++.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <termios.h>
#include <unistd.h>
#include <utility>

namespace {

constexpr std::size_t MAX_PASSWORD_SIZE = 1024;

class UniqueFd {
public:
    explicit UniqueFd(int fd = -1) noexcept : fd_(fd) {}

    ~UniqueFd() {
        if(fd_ >= 0)
            static_cast<void>(close(fd_));
    }

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    [[nodiscard]] int get() const noexcept {
        return fd_;
    }

    void reset(int fd = -1) noexcept {
        if(fd_ >= 0)
            static_cast<void>(close(fd_));
        fd_ = fd;
    }

private:
    int fd_;
};

class HiddenInput {
public:
    HiddenInput() {
        if(tcgetattr(STDIN_FILENO, &original_) != 0) {
            throw std::system_error(
                errno,
                std::generic_category(),
                "read terminal settings"
            );
        }
        termios hidden = original_;
        hidden.c_lflag &= static_cast<tcflag_t>(~ECHO);
        if(tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0) {
            throw std::system_error(
                errno,
                std::generic_category(),
                "disable terminal echo"
            );
        }
        active_ = true;
    }

    ~HiddenInput() {
        explicit_bzero(input_.data(), input_.size());
        restore();
    }

    HiddenInput(const HiddenInput&) = delete;
    HiddenInput& operator=(const HiddenInput&) = delete;

    [[nodiscard]] std::string_view read() {
        if(!std::cin.getline(input_.data(), input_.size()))
            throw std::runtime_error("Unable to read password");
        const std::streamsize count = std::cin.gcount();
        if(count <= 0)
            throw std::runtime_error("Unable to read password");
        const std::size_t size = static_cast<std::size_t>(count - 1);
        if(size > MAX_PASSWORD_SIZE)
            throw std::runtime_error("Password is too long");
        if(!restore())
            throw std::runtime_error("Unable to restore terminal echo");
        std::fputc('\n', stderr);
        return {input_.data(), size};
    }

private:
    bool restore() noexcept {
        if(!active_)
            return true;
        if(tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_) != 0)
            return false;
        active_ = false;
        return true;
    }

    std::array<char, MAX_PASSWORD_SIZE + 2> input_{};
    termios original_{};
    bool active_ = false;
};

void cancel_interaction(
    sdbus::IProxy& proxy,
    uint64_t generation,
    uint64_t request_id
) {
    proxy.callMethod(
        std::string(vauth::dbus::CANCEL_INTERACTION_METHOD)
    ).onInterface(
        std::string(vauth::dbus::INTERFACE_NAME)
    ).withArguments(generation, request_id);
}

std::string display_message(
    const std::string& state,
    const std::string& operation,
    const std::string& relying_party_id
) {
    const std::string target = relying_party_id.empty()
        ? std::string{}
        : " for " + relying_party_id;
    if(state == "presence_required")
        return "User presence required" + target;
    if(state == "presence_approved")
        return "User presence approved" + target;
    if(state == "presence_denied")
        return "User presence denied" + target;
    if(state == "verification_started")
        return "User verification started" + target;
    if(state == "fingerprint_required")
        return "Touch the fingerprint reader" + target;
    if(state == "fingerprint_failed")
        return "Fingerprint was not recognized" + target;
    if(state == "password_required")
        return "Password is required" + target;
    if(state == "verification_succeeded")
        return "User verification succeeded" + target;
    if(state == "verification_failed")
        return "User verification failed" + target;
    if(state == "cancelled")
        return "Operation was cancelled" + target;
    if(state == "timed_out")
        return "Operation timed out" + target;
    return "State " + state + " during " + operation + target;
}

void respond_to_presence(
    sdbus::IProxy& proxy,
    uint64_t generation,
    uint64_t request_id
) {
    std::cout << "Allow this operation? [y/N/cancel] " << std::flush;
    std::string response;
    if(!std::getline(std::cin, response))
        response.clear();

    if(response == "c" || response == "cancel") {
        cancel_interaction(proxy, generation, request_id);
        return;
    }

    const bool approved = response == "y" || response == "yes";
    proxy.callMethod(
        std::string(vauth::dbus::RESPOND_TO_PRESENCE_METHOD)
    ).onInterface(
        std::string(vauth::dbus::INTERFACE_NAME)
    ).withArguments(generation, request_id, approved);
}

void submit_password(
    sdbus::IProxy& proxy,
    uint64_t generation,
    uint64_t request_id
) {
    std::cout << "Password: " << std::flush;
    HiddenInput input;
    const std::string_view password = input.read();

    std::array<int, 2> descriptors{};
    if(pipe2(descriptors.data(), O_CLOEXEC) != 0) {
        throw std::system_error(
            errno,
            std::generic_category(),
            "create password pipe"
        );
    }
    UniqueFd read_end(descriptors[0]);
    UniqueFd write_end(descriptors[1]);

    std::size_t written = 0;
    while(written < password.size()) {
        const ssize_t count = write(
            write_end.get(),
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
            "write password pipe"
        );
    }
    write_end.reset();

    proxy.callMethod(
        std::string(vauth::dbus::SUBMIT_PASSWORD_METHOD)
    ).onInterface(
        std::string(vauth::dbus::INTERFACE_NAME)
    ).withArguments(
        generation,
        request_id,
        sdbus::UnixFd{read_end.get()}
    );
}

}

int main() {
    try {
        auto connection = sdbus::createSystemBusConnection();
        auto proxy = sdbus::createProxy(
            *connection,
            sdbus::ServiceName{std::string(vauth::dbus::SERVICE_NAME)},
            sdbus::ObjectPath{std::string(vauth::dbus::OBJECT_PATH)}
        );

        uint64_t generation = 0;
        auto state_slot = proxy->uponSignal(
            std::string(vauth::dbus::STATE_SIGNAL)
        ).onInterface(
            std::string(vauth::dbus::INTERFACE_NAME)
        ).call(
            [&generation, proxy = proxy.get()](
                uint64_t signal_generation,
                uint64_t request_id,
                const std::string& state,
                const std::string& operation,
                const std::string& relying_party_id
            ) {
                if(signal_generation != generation)
                    return;
                std::cout << "D-Bus state: " << state
                          << " [request " << request_id << "] ("
                          << operation << ")\n"
                          << display_message(
                              state,
                              operation,
                              relying_party_id
                          ) << '\n';
                if(state == "presence_required") {
                    try {
                        respond_to_presence(
                            *proxy,
                            generation,
                            request_id
                        );
                    } catch(const std::exception& error) {
                        std::cerr << "Presence response failed: "
                                  << error.what() << '\n';
                    }
                } else if(state == "password_required") {
                    try {
                        submit_password(*proxy, generation, request_id);
                    } catch(const std::exception& error) {
                        std::cerr << "Password submission failed: "
                                  << error.what() << '\n';
                        try {
                            cancel_interaction(
                                *proxy,
                                generation,
                                request_id
                            );
                        } catch(...) {
                        }
                    }
                }
            },
            sdbus::return_slot
        );

        proxy->callMethod(
            std::string(vauth::dbus::REGISTER_METHOD)
        ).onInterface(
            std::string(vauth::dbus::INTERFACE_NAME)
        ).storeResultsTo(generation);

        if(generation == 0)
            throw std::runtime_error("Daemon returned an invalid generation");
        std::cout << "Registered vAuth UI agent generation "
                  << generation << "\n";
        connection->enterEventLoop();
        return 0;
    } catch(const std::exception& error) {
        std::cerr << "vauth-agent-debug: " << error.what() << '\n';
        return 1;
    }
}
