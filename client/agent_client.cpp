#include "agent_client.hpp"

#include "dbus/constants.hpp"

#include <sdbus-c++/sdbus-c++.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <deque>
#include <exception>
#include <fcntl.h>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <system_error>
#include <unistd.h>
#include <utility>

namespace vauth::client {
namespace {

constexpr std::size_t MAX_PASSWORD_SIZE = 1024;
constexpr std::size_t MAX_EARLY_EVENTS = 32;

class UniqueFd {
public:
    explicit UniqueFd(int fd = -1) noexcept : fd_(fd) {}

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
    int fd_;
};

std::pair<UniqueFd, UniqueFd> make_pipe() {
    std::array<int, 2> descriptors{};
    if(pipe2(descriptors.data(), O_CLOEXEC) != 0) {
        throw std::system_error(
            errno,
            std::generic_category(),
            "create password pipe"
        );
    }
    return {UniqueFd(descriptors[0]), UniqueFd(descriptors[1])};
}

void write_all(int fd, std::span<const uint8_t> bytes) {
    std::size_t written = 0;
    while(written < bytes.size()) {
        const ssize_t count = write(
            fd,
            bytes.data() + written,
            bytes.size() - written
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
}

} // namespace

class AgentClient::Impl {
public:
    explicit Impl(EventHandler handler)
        : handler_(std::move(handler)),
          connection_(sdbus::createSystemBusConnection()),
          proxy_(sdbus::createProxy(
              *connection_,
              sdbus::ServiceName{std::string(vauth::dbus::SERVICE_NAME)},
              sdbus::ObjectPath{std::string(vauth::dbus::OBJECT_PATH)}
          )) {
        stateSlot_ = proxy_->uponSignal(
            std::string(vauth::dbus::STATE_SIGNAL)
        ).onInterface(
            std::string(vauth::dbus::INTERFACE_NAME)
        ).call(
            [this](
                uint64_t signal_generation,
                uint64_t request_id,
                const std::string& state_name,
                const std::string& operation,
                const std::string& relying_party_id
            ) {
                const auto state = parse_interaction_state(state_name);
                if(!state)
                    return;

                InteractionEvent event{
                    .generation = signal_generation,
                    .requestId = request_id,
                    .state = *state,
                    .operation = operation,
                    .relyingPartyId = relying_party_id
                };
                receive_event(std::move(event));
            },
            sdbus::return_slot
        );

        proxy_->callMethod(
            std::string(vauth::dbus::REGISTER_METHOD)
        ).onInterface(
            std::string(vauth::dbus::INTERFACE_NAME)
        ).storeResultsTo(generation_);
        if(generation_ == 0)
            throw std::runtime_error("Daemon returned an invalid generation");
        std::deque<InteractionEvent> early_events;
        {
            std::lock_guard lock(stateMutex_);
            if(earlyEventsOverflowed_) {
                throw std::runtime_error(
                    "Too many interaction events arrived during registration"
                );
            }
            tracker_ = std::make_unique<InteractionTracker>(generation_);
            early_events.swap(earlyEvents_);
        }
        for(auto& event : early_events)
            receive_event(std::move(event));
        connection_->enterEventLoopAsync();
    }

    ~Impl() {
        try {
            proxy_->callMethod(
                std::string(vauth::dbus::UNREGISTER_METHOD)
            ).onInterface(
                std::string(vauth::dbus::INTERFACE_NAME)
            ).withArguments(generation_);
        } catch(...) {
        }
        try {
            connection_->leaveEventLoop();
        } catch(...) {
        }
    }

    [[nodiscard]] uint64_t generation() const noexcept {
        return generation_;
    }

    [[nodiscard]] bool is_active(uint64_t request_id) const noexcept {
        std::lock_guard lock(stateMutex_);
        return tracker_ && tracker_->is_active(request_id);
    }

    void respond_to_presence(uint64_t request_id, bool approved) {
        require_active(request_id);
        proxy_->callMethod(
            std::string(vauth::dbus::RESPOND_TO_PRESENCE_METHOD)
        ).onInterface(
            std::string(vauth::dbus::INTERFACE_NAME)
        ).withArguments(generation_, request_id, approved);
    }

    void submit_password(
        uint64_t request_id,
        std::span<const uint8_t> password
    ) {
        require_active(request_id);
        if(
            password.size() > MAX_PASSWORD_SIZE ||
            std::ranges::find(password, uint8_t{0}) != password.end()
        ) {
            throw std::invalid_argument("Invalid password response");
        }
        auto [read_end, write_end] = make_pipe();
        write_all(write_end.get(), password);
        write_end.reset();
        proxy_->callMethod(
            std::string(vauth::dbus::SUBMIT_PASSWORD_METHOD)
        ).onInterface(
            std::string(vauth::dbus::INTERFACE_NAME)
        ).withArguments(
            generation_,
            request_id,
            sdbus::UnixFd{read_end.get()}
        );
    }

    void cancel(uint64_t request_id) {
        require_active(request_id);
        proxy_->callMethod(
            std::string(vauth::dbus::CANCEL_INTERACTION_METHOD)
        ).onInterface(
            std::string(vauth::dbus::INTERFACE_NAME)
        ).withArguments(generation_, request_id);
    }

private:
    void receive_event(InteractionEvent event) {
        {
            std::lock_guard lock(stateMutex_);
            if(!tracker_) {
                if(earlyEvents_.size() == MAX_EARLY_EVENTS) {
                    earlyEventsOverflowed_ = true;
                    return;
                }
                earlyEvents_.push_back(std::move(event));
                return;
            }
            if(!tracker_->accept(event))
                return;
        }
#ifdef DEBUG
        std::cerr << "D-Bus: received StateChanged\n";
#endif
        try {
            handler_(std::move(event));
        } catch(const std::exception& error) {
            std::cerr << "vAuth UI event dispatch failed: "
                      << error.what() << '\n';
        }
    }

    void require_active(uint64_t request_id) const {
        if(request_id == 0 || !is_active(request_id))
            throw std::runtime_error("Interaction request is no longer active");
    }

    EventHandler handler_;
    std::unique_ptr<sdbus::IConnection> connection_;
    std::unique_ptr<sdbus::IProxy> proxy_;
    sdbus::Slot stateSlot_;
    uint64_t generation_ = 0;
    mutable std::mutex stateMutex_;
    std::unique_ptr<InteractionTracker> tracker_;
    std::deque<InteractionEvent> earlyEvents_;
    bool earlyEventsOverflowed_ = false;
};

AgentClient::AgentClient(EventHandler handler)
    : impl_(std::make_unique<Impl>(std::move(handler))) {}

AgentClient::~AgentClient() = default;

uint64_t AgentClient::generation() const noexcept {
    return impl_->generation();
}

bool AgentClient::is_active(uint64_t request_id) const noexcept {
    return impl_->is_active(request_id);
}

void AgentClient::respond_to_presence(
    uint64_t request_id,
    bool approved
) {
    impl_->respond_to_presence(request_id, approved);
}

void AgentClient::submit_password(
    uint64_t request_id,
    std::span<const uint8_t> password
) {
    impl_->submit_password(request_id, password);
}

void AgentClient::cancel(uint64_t request_id) {
    impl_->cancel(request_id);
}

} // namespace vauth::client
