#include "agent_service.hpp"

#include "agent_registry.hpp"
#include "cancellation.hpp"
#include "constants.hpp"
#include "interaction_registry.hpp"
#include "secret_pipe.hpp"

#include <sdbus-c++/sdbus-c++.h>
#include <systemd/sd-login.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <exception>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <poll.h>
#include <pwd.h>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <string_view>
#include <sys/eventfd.h>
#include <system_error>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

namespace vauth::dbus {
namespace {

constexpr std::size_t MAX_ACCOUNT_BUFFER_SIZE = 1024 * 1024;
constexpr auto AGENT_STARTUP_GRACE = std::chrono::seconds(2);
#ifdef DEBUG
constexpr std::string_view ANSI_PURPLE = "\x1b[35m";
constexpr std::string_view ANSI_RESET = "\x1b[0m";
#endif

class UniqueFd {
public:
    explicit UniqueFd(int fd) : fd_(fd) {
        if(fd_ < 0) {
            throw std::system_error(
                errno,
                std::generic_category(),
                "eventfd"
            );
        }
    }

    ~UniqueFd() {
        if(fd_ >= 0)
            static_cast<void>(close(fd_));
    }

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    [[nodiscard]] int get() const noexcept {
        return fd_;
    }

private:
    int fd_;
};

using CAllocatedString = std::unique_ptr<char, decltype(&std::free)>;

[[noreturn]] void throw_login_error(int result, const char* operation) {
    throw std::system_error(
        -result,
        std::generic_category(),
        operation
    );
}

CAllocatedString session_for_peer(pid_t pid, uid_t uid) {
    char* raw_session = nullptr;
    int result = sd_pid_get_session(pid, &raw_session);
    if(result < 0) {
        result = sd_uid_get_display(uid, &raw_session);
        if(result < 0)
            throw_login_error(result, "resolve agent login session");
    }
    if(raw_session == nullptr || raw_session[0] == '\0') {
        std::free(raw_session);
        throw std::runtime_error("Agent login session is empty");
    }
    return CAllocatedString(raw_session, &std::free);
}

std::string username_for_uid(uid_t uid) {
    long requested_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    std::size_t buffer_size = requested_size > 0
        ? static_cast<std::size_t>(requested_size)
        : 16384;
    buffer_size = std::min(buffer_size, MAX_ACCOUNT_BUFFER_SIZE);

    while(true) {
        std::vector<char> buffer(buffer_size);
        passwd account{};
        passwd* result = nullptr;
        const int status = getpwuid_r(
            uid,
            &account,
            buffer.data(),
            buffer.size(),
            &result
        );
        if(status == 0 && result != nullptr)
            return account.pw_name;
        if(status != ERANGE || buffer_size == MAX_ACCOUNT_BUFFER_SIZE) {
            if(status != 0) {
                throw std::system_error(
                    status,
                    std::generic_category(),
                    "getpwuid_r"
                );
            }
            throw std::runtime_error("Unable to resolve agent user name");
        }
        buffer_size = std::min(
            buffer_size * 2,
            MAX_ACCOUNT_BUFFER_SIZE
        );
    }
}

void validate_active_local_session(const char* session, uid_t peer_uid) {
    uid_t session_uid = 0;
    const int uid_result = sd_session_get_uid(session, &session_uid);
    if(uid_result < 0)
        throw_login_error(uid_result, "resolve agent session user");
    if(session_uid != peer_uid)
        throw std::runtime_error("Agent UID does not own its login session");

    const int active = sd_session_is_active(session);
    if(active < 0)
        throw_login_error(active, "inspect agent session activity");
    if(active != 1)
        throw std::runtime_error("Agent login session is not active");

    const int remote = sd_session_is_remote(session);
    if(remote < 0)
        throw_login_error(remote, "inspect agent session locality");
    if(remote != 0)
        throw std::runtime_error("Remote login sessions cannot register agents");
}

AgentPeer resolve_peer(const sdbus::MethodCall& call) {
    const char* sender = call.getSender();
    if(sender == nullptr || sender[0] != ':')
        throw std::runtime_error("Agent has no authenticated unique bus name");

    const uid_t uid = call.getCredsUid();
    const pid_t pid = call.getCredsPid();
    if(pid <= 0)
        throw std::runtime_error("Agent has no authenticated process ID");
    if(static_cast<uintmax_t>(uid) > std::numeric_limits<uint32_t>::max())
        throw std::runtime_error("Agent UID is out of range");

    auto session = session_for_peer(pid, uid);
    validate_active_local_session(session.get(), uid);
    return {
        .uid = static_cast<uint32_t>(uid),
        .userName = username_for_uid(uid),
        .sessionId = session.get(),
        .busName = sender
    };
}

bool session_is_still_active(const UserContext& context) noexcept {
    if(!context.session)
        return false;

    uid_t session_uid = 0;
    const int uid_result = sd_session_get_uid(
        context.session->sessionId.c_str(),
        &session_uid
    );
    const int active = sd_session_is_active(
        context.session->sessionId.c_str()
    );
    const int remote = sd_session_is_remote(
        context.session->sessionId.c_str()
    );
    return
        uid_result >= 0 &&
        session_uid == static_cast<uid_t>(context.uid) &&
        active == 1 &&
        remote == 0;
}

struct StateEvent {
    UserContext user;
    uint64_t requestId;
    UserInteractionOperation operation;
    UserInteractionState state;
    std::string relyingPartyId;
};

}

class AgentService::Impl {
public:
    Impl()
        : connection_(sdbus::createSystemBusConnection(
              sdbus::ServiceName{std::string(SERVICE_NAME)}
          )),
          object_(sdbus::createObject(
              *connection_,
              sdbus::ObjectPath{std::string(OBJECT_PATH)}
          )),
          wakeFd_(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK)) {
        auto register_method = sdbus::registerMethod(
            std::string(REGISTER_METHOD)
        );
        register_method.outputSignature = sdbus::Signature{"t"};
        register_method.outputParamNames = {"generation"};
        register_method.callbackHandler = [this](sdbus::MethodCall call) {
            register_agent(std::move(call));
        };

        auto unregister_method = sdbus::registerMethod(
            std::string(UNREGISTER_METHOD)
        );
        unregister_method.callbackHandler = [this](sdbus::MethodCall call) {
            unregister_agent(std::move(call));
        };

        auto state_signal = sdbus::registerSignal(std::string(STATE_SIGNAL));
        state_signal.withParameters<
            uint64_t,
            uint64_t,
            std::string,
            std::string,
            std::string
        >(
            "generation",
            "requestId",
            "state",
            "operation",
            "relyingPartyId"
        );

        auto presence_method = sdbus::registerMethod(
            std::string(RESPOND_TO_PRESENCE_METHOD)
        );
        presence_method.inputSignature = sdbus::Signature{"ttb"};
        presence_method.inputParamNames = {
            "generation",
            "requestId",
            "approved"
        };
        presence_method.callbackHandler = [this](sdbus::MethodCall call) {
            respond_to_presence(std::move(call));
        };

        auto password_method = sdbus::registerMethod(
            std::string(SUBMIT_PASSWORD_METHOD)
        );
        password_method.inputSignature = sdbus::Signature{"tth"};
        password_method.inputParamNames = {
            "generation",
            "requestId",
            "passwordPipe"
        };
        password_method.callbackHandler = [this](sdbus::MethodCall call) {
            submit_password(std::move(call));
        };

        auto cancel_method = sdbus::registerMethod(
            std::string(CANCEL_INTERACTION_METHOD)
        );
        cancel_method.inputSignature = sdbus::Signature{"tt"};
        cancel_method.inputParamNames = {"generation", "requestId"};
        cancel_method.callbackHandler = [this](sdbus::MethodCall call) {
            cancel_interaction(std::move(call));
        };

        vtable_ = object_->addVTable(
            std::move(register_method),
            std::move(unregister_method),
            std::move(presence_method),
            std::move(password_method),
            std::move(cancel_method),
            std::move(state_signal)
        ).forInterface(std::string(INTERFACE_NAME), sdbus::return_slot);

        nameOwnerChanged_ = connection_->addMatch(
            "type='signal',sender='org.freedesktop.DBus',"
            "interface='org.freedesktop.DBus',member='NameOwnerChanged'",
            [this](sdbus::Message message) {
                std::string name;
                std::string old_owner;
                std::string new_owner;
                message >> name >> old_owner >> new_owner;
                if(!old_owner.empty() && new_owner.empty())
                    unregister_disconnected_agent(name);
            },
            sdbus::return_slot
        );

        thread_ = std::jthread([this](std::stop_token stop) {
            event_loop(stop);
        });
    }

    ~Impl() {
        thread_.request_stop();
        wake();
        if(thread_.joinable())
            thread_.join();
    }

    [[nodiscard]] std::optional<UserContext> current_context() {
        throw_if_failed();
        auto context = registry_.wait_for_current(AGENT_STARTUP_GRACE);
        throw_if_failed();
        if(!context)
            return std::nullopt;
        if(session_is_still_active(*context))
            return context;

        const std::string bus_name = context->session->interactionAgentId;
        interactions_.clear_for(*context);
        static_cast<void>(registry_.unregister_agent(bus_name));
#ifdef DEBUG
        std::cerr << ANSI_PURPLE
                  << "D-Bus: discarded inactive user-interaction agent"
                  << ANSI_RESET << '\n';
#endif
        return std::nullopt;
    }

    [[nodiscard]] uint64_t begin_interaction(
        const UserContext& user,
        const UserInteractionRequest& request
    ) {
        throw_if_failed();
        if(request.requestId != 0)
            throw std::invalid_argument("Interaction already has a request ID");
        if(!user.session || !registry_.is_current(user))
            return 0;
        return interactions_.begin(
            user,
            request.operation,
            request.relyingPartyId
        );
    }

    void publish_state(
        const UserContext& user,
        const UserInteractionRequest& request,
        UserInteractionState state
    ) {
        throw_if_failed();
        if(
            request.requestId == 0 ||
            !user.session ||
            !registry_.is_current(user)
        ) {
            return;
        }
        if(!interactions_.transition(
            user,
            request.requestId,
            state
        )) {
            return;
        }

        {
            std::lock_guard lock(queueMutex_);
            events_.push_back({
                .user = user,
                .requestId = request.requestId,
                .operation = request.operation,
                .state = state,
                .relyingPartyId = std::string(request.relyingPartyId)
            });
        }
        wake();
    }

    void end_interaction(
        const UserContext& user,
        const UserInteractionRequest& request
    ) noexcept {
        static_cast<void>(interactions_.end(
            user,
            request.requestId
        ));
    }

    [[nodiscard]] UserInteractionResult wait_for_presence(
        const UserContext& user,
        const UserInteractionRequest& request,
        std::stop_token stop,
        std::chrono::steady_clock::duration timeout
    ) {
        throw_if_failed();
        switch(interactions_.wait_for_presence(
            user,
            request.requestId,
            stop,
            timeout
        )) {
            case PresenceWaitResult::approved:
                return UserInteractionResult::approved;
            case PresenceWaitResult::denied:
                return UserInteractionResult::denied;
            case PresenceWaitResult::timed_out:
                throw UserActionTimedOut{};
            case PresenceWaitResult::client_cancelled:
                return UserInteractionResult::cancelled;
            case PresenceWaitResult::platform_cancelled:
                throw OperationCancelled{};
            case PresenceWaitResult::invalidated:
                throw UserInteractionUnavailable{};
        }
        throw std::logic_error("Unknown presence response state");
    }

    [[nodiscard]] vauth::uv::SensitiveBytes wait_for_password(
        const UserContext& user,
        const UserInteractionRequest& request,
        std::stop_token stop,
        std::chrono::steady_clock::duration timeout
    ) {
        throw_if_failed();
        auto result = interactions_.wait_for_password(
            user,
            request.requestId,
            stop,
            timeout
        );
        switch(result.status) {
            case PasswordWaitStatus::provided:
                return std::move(result.password);
            case PasswordWaitStatus::timed_out:
                throw UserActionTimedOut{};
            case PasswordWaitStatus::client_cancelled:
                throw UserInteractionCancelled{};
            case PasswordWaitStatus::platform_cancelled:
                throw OperationCancelled{};
            case PasswordWaitStatus::invalidated:
                throw UserInteractionUnavailable{};
        }
        throw std::logic_error("Unknown password response state");
    }

    [[nodiscard]] bool cancellation_requested(
        const UserContext& user,
        const UserInteractionRequest& request
    ) const noexcept {
        try {
            throw_if_failed();
            if(!registry_.is_current(user))
                return true;
            return interactions_.cancellation_requested(
                user,
                request.requestId
            );
        } catch(...) {
            return true;
        }
    }

private:
    [[nodiscard]] UserContext registered_caller(
        const sdbus::MethodCall& call,
        uint64_t generation
    ) {
        const char* sender = call.getSender();
        const auto current = registry_.current_context();
        if(
            sender == nullptr ||
            sender[0] != ':' ||
            !current ||
            !current->session ||
            current->session->interactionAgentId != sender ||
            current->session->generation != generation
        ) {
            throw std::runtime_error("Calling agent registration is stale");
        }
        if(!session_is_still_active(*current)) {
            interactions_.clear_for(*current);
            static_cast<void>(registry_.unregister_agent(sender));
            throw std::runtime_error("Calling agent session is not active");
        }
        return *current;
    }

    void respond_to_presence(sdbus::MethodCall call) noexcept {
        try {
            uint64_t generation = 0;
            uint64_t request_id = 0;
            bool approved = false;
            call >> generation >> request_id >> approved;
            const UserContext user = registered_caller(call, generation);
            interactions_.respond_to_presence(user, request_id, approved);
            call.createReply().send();
#ifdef DEBUG
            std::cerr << ANSI_PURPLE
                      << "D-Bus: received RespondToPresence"
                      << ANSI_RESET << '\n';
#endif
        } catch(const std::exception& error) {
            try {
                call.createErrorReply(sdbus::Error{
                    sdbus::Error::Name{
                        "org.lamellix.vAuth.Error.InvalidInteraction"
                    },
                    error.what()
                }).send();
            } catch(...) {
            }
        }
    }

    void submit_password(sdbus::MethodCall call) noexcept {
        try {
            uint64_t generation = 0;
            uint64_t request_id = 0;
            sdbus::UnixFd password_pipe;
            call >> generation >> request_id >> password_pipe;
            const UserContext user = registered_caller(call, generation);
            interactions_.submit_password(
                user,
                request_id,
                read_secret_pipe(password_pipe.get())
            );
            call.createReply().send();
#ifdef DEBUG
            std::cerr << ANSI_PURPLE
                      << "D-Bus: received SubmitPassword"
                      << ANSI_RESET << '\n';
#endif
        } catch(const std::exception& error) {
            try {
                call.createErrorReply(sdbus::Error{
                    sdbus::Error::Name{
                        "org.lamellix.vAuth.Error.InvalidInteraction"
                    },
                    error.what()
                }).send();
            } catch(...) {
            }
        }
    }

    void cancel_interaction(sdbus::MethodCall call) noexcept {
        try {
            uint64_t generation = 0;
            uint64_t request_id = 0;
            call >> generation >> request_id;
            const UserContext user = registered_caller(call, generation);
            interactions_.request_cancel(user, request_id);
            call.createReply().send();
#ifdef DEBUG
            std::cerr << ANSI_PURPLE
                      << "D-Bus: received CancelInteraction"
                      << ANSI_RESET << '\n';
#endif
        } catch(const std::exception& error) {
            try {
                call.createErrorReply(sdbus::Error{
                    sdbus::Error::Name{
                        "org.lamellix.vAuth.Error.InvalidInteraction"
                    },
                    error.what()
                }).send();
            } catch(...) {
            }
        }
    }

    void register_agent(sdbus::MethodCall call) noexcept {
        try {
            AgentPeer peer = resolve_peer(call);
            if(auto current = registry_.current_context()) {
                if(!session_is_still_active(*current)) {
                    interactions_.clear_for(*current);
                    static_cast<void>(registry_.unregister_agent(
                        current->session->interactionAgentId
                    ));
                }
            }
            const UserContext context = registry_.register_agent(
                std::move(peer)
            );
            auto reply = call.createReply();
            reply << context.session->generation;
            reply.send();
#ifdef DEBUG
            std::cerr << ANSI_PURPLE
                      << "D-Bus: registered user-interaction agent for UID "
                      << context.uid << ANSI_RESET << '\n';
#endif
        } catch(const std::exception& error) {
            try {
                call.createErrorReply(sdbus::Error{
                    sdbus::Error::Name{
                        "org.lamellix.vAuth.Error.RegistrationFailed"
                    },
                    error.what()
                }).send();
            } catch(...) {
            }
        }
    }

    void unregister_agent(sdbus::MethodCall call) noexcept {
        try {
            const char* sender = call.getSender();
            if(sender == nullptr || sender[0] != ':')
                throw std::runtime_error("Agent has no unique bus name");
            const auto current = registry_.current_context();
            if(
                !current ||
                !current->session ||
                current->session->interactionAgentId != sender
            ) {
                throw std::runtime_error("Calling agent is not registered");
            }
            interactions_.clear_for(*current);
            if(!registry_.unregister_agent(sender))
                throw std::runtime_error("Calling agent is not registered");
            call.createReply().send();
#ifdef DEBUG
            std::cerr << ANSI_PURPLE
                      << "D-Bus: unregistered user-interaction agent"
                      << ANSI_RESET << '\n';
#endif
        } catch(const std::exception& error) {
            try {
                call.createErrorReply(sdbus::Error{
                    sdbus::Error::Name{
                        "org.lamellix.vAuth.Error.NotRegistered"
                    },
                    error.what()
                }).send();
            } catch(...) {
            }
        }
    }

    void unregister_disconnected_agent(const std::string& bus_name) noexcept {
        const auto current = registry_.current_context();
        if(
            current &&
            current->session &&
            current->session->interactionAgentId == bus_name
        ) {
            interactions_.clear_for(*current);
        }
        if(!registry_.unregister_agent(bus_name))
            return;
#ifdef DEBUG
        std::cerr << ANSI_PURPLE
                  << "D-Bus: user-interaction agent disconnected"
                  << ANSI_RESET << '\n';
#endif
    }

    void wake() noexcept {
        const uint64_t value = 1;
        ssize_t result;
        do {
            result = write(wakeFd_.get(), &value, sizeof(value));
        } while(result < 0 && errno == EINTR);
    }

    void drain_wake_fd() noexcept {
        uint64_t value = 0;
        while(read(wakeFd_.get(), &value, sizeof(value)) < 0 && errno == EINTR) {
        }
    }

    void send_queued_events() {
        std::deque<StateEvent> events;
        {
            std::lock_guard lock(queueMutex_);
            events.swap(events_);
        }

        for(const auto& event : events) {
            if(!event.user.session || !registry_.is_current(event.user))
                continue;

            auto signal = object_->createSignal(
                sdbus::InterfaceName{std::string(INTERFACE_NAME)},
                sdbus::SignalName{std::string(STATE_SIGNAL)}
            );
            signal.setDestination(event.user.session->interactionAgentId);
            signal
                << event.user.session->generation
                << event.requestId
                << std::string(user_interaction_state_name(event.state))
                << std::string(user_interaction_operation_name(event.operation))
                << event.relyingPartyId;
            signal.send();
#ifdef DEBUG
            std::cerr << ANSI_PURPLE << "D-Bus: sent StateChanged ("
                      << user_interaction_state_name(event.state) << ')'
                      << ANSI_RESET << '\n';
#endif
        }
    }

    void event_loop(std::stop_token stop) noexcept {
        std::stop_callback wake_on_stop(stop, [this] { wake(); });
        try {
            while(!stop.stop_requested()) {
                const auto bus = connection_->getEventLoopPollData();
                std::array<pollfd, 3> descriptors{};
                nfds_t count = 0;
                if(bus.fd >= 0) {
                    descriptors[count++] = {
                        .fd = bus.fd,
                        .events = bus.events,
                        .revents = 0
                    };
                }
                if(bus.eventFd >= 0 && bus.eventFd != bus.fd) {
                    descriptors[count++] = {
                        .fd = bus.eventFd,
                        .events = POLLIN,
                        .revents = 0
                    };
                }
                descriptors[count++] = {
                    .fd = wakeFd_.get(),
                    .events = POLLIN,
                    .revents = 0
                };

                int poll_result;
                do {
                    poll_result = poll(
                        descriptors.data(),
                        count,
                        bus.getPollTimeout()
                    );
                } while(poll_result < 0 && errno == EINTR);
                if(poll_result < 0) {
                    throw std::system_error(
                        errno,
                        std::generic_category(),
                        "poll D-Bus"
                    );
                }

                if(descriptors[count - 1].revents & POLLIN)
                    drain_wake_fd();
                if(stop.stop_requested())
                    break;

                while(connection_->processPendingEvent()) {
                }
                send_queued_events();
            }
        } catch(const std::exception& error) {
            record_failure(error.what());
        } catch(...) {
            record_failure("unknown D-Bus event-loop failure");
        }
    }

    void record_failure(std::string message) noexcept {
        {
            std::lock_guard lock(failureMutex_);
            failure_ = std::move(message);
        }
        if(auto context = registry_.current_context()) {
            interactions_.clear_for(*context);
            static_cast<void>(registry_.unregister_agent(
                context->session->interactionAgentId
            ));
        }
#ifdef DEBUG
        std::cerr << ANSI_PURPLE << "D-Bus: service event loop stopped"
                  << ANSI_RESET << '\n';
#endif
    }

    void throw_if_failed() const {
        std::lock_guard lock(failureMutex_);
        if(failure_)
            throw std::runtime_error("D-Bus service failed: " + *failure_);
    }

    AgentRegistry registry_;
    InteractionRegistry interactions_;
    std::unique_ptr<sdbus::IConnection> connection_;
    std::unique_ptr<sdbus::IObject> object_;
    sdbus::Slot vtable_;
    sdbus::Slot nameOwnerChanged_;
    UniqueFd wakeFd_;
    std::mutex queueMutex_;
    std::deque<StateEvent> events_;
    mutable std::mutex failureMutex_;
    std::optional<std::string> failure_;
    std::jthread thread_;
};

AgentService::AgentService() : impl_(std::make_unique<Impl>()) {}

AgentService::~AgentService() = default;

std::optional<UserContext> AgentService::current_context() {
    return impl_->current_context();
}

uint64_t AgentService::begin_interaction(
    const UserContext& user,
    const UserInteractionRequest& request
) {
    return impl_->begin_interaction(user, request);
}

void AgentService::publish_state(
    const UserContext& user,
    const UserInteractionRequest& request,
    UserInteractionState state
) {
    impl_->publish_state(user, request, state);
}

void AgentService::end_interaction(
    const UserContext& user,
    const UserInteractionRequest& request
) noexcept {
    impl_->end_interaction(user, request);
}

UserInteractionResult AgentService::wait_for_presence(
    const UserContext& user,
    const UserInteractionRequest& request,
    std::stop_token stop,
    std::chrono::steady_clock::duration timeout
) {
    return impl_->wait_for_presence(user, request, stop, timeout);
}

vauth::uv::SensitiveBytes AgentService::wait_for_password(
    const UserContext& user,
    const UserInteractionRequest& request,
    std::stop_token stop,
    std::chrono::steady_clock::duration timeout
) {
    return impl_->wait_for_password(user, request, stop, timeout);
}

bool AgentService::cancellation_requested(
    const UserContext& user,
    const UserInteractionRequest& request
) const noexcept {
    return impl_->cancellation_requested(user, request);
}

}
