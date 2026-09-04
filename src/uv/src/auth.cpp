#include "auth.hpp"

#include "auth_handler.hpp"
#include "auth_handler_status.hpp"
#include "cancellable_process.hpp"
#include "cancellation.hpp"
#include "keepalive.hpp"

#include <chrono>
#include <cerrno>
#include <limits>
#include <pwd.h>
#include <security/_pam_types.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <termios.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

constexpr auto USER_ACTION_TIMEOUT = std::chrono::seconds(30);

void publish_state(
    UserInteractionStateSink* sink,
    const UserContext& user,
    const UserInteractionRequest& request,
    UserInteractionState state
) {
    if(sink != nullptr)
        sink->publish_state(user, request, state);
}

bool context_is_still_current(
    UserContextProvider* provider,
    const UserContext& user
) {
    if(!user.session)
        return true;
    if(provider == nullptr)
        return false;
    const auto current = provider->current_context();
    return current && current->binding() == user.binding();
}

class InteractionScope {
public:
    InteractionScope(
        UserInteractionStateSink* sink,
        const UserContext& user,
        const UserInteractionRequest& request
    ) : sink_(sink), user_(user), request_(request) {
        if(sink_ != nullptr)
            request_.requestId = sink_->begin_interaction(user_, request_);
    }

    ~InteractionScope() {
        if(sink_ != nullptr)
            sink_->end_interaction(user_, request_);
    }

    InteractionScope(const InteractionScope&) = delete;
    InteractionScope& operator=(const InteractionScope&) = delete;

    [[nodiscard]] const UserInteractionRequest& request() const noexcept {
        return request_;
    }

private:
    UserInteractionStateSink* sink_;
    const UserContext& user_;
    UserInteractionRequest request_;
};

class TerminalStateRestorer {
public:
    TerminalStateRestorer() noexcept {
        valid_ = tcgetattr(STDIN_FILENO, &original_) == 0;
    }

    ~TerminalStateRestorer() {
        if(valid_)
            static_cast<void>(tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_));
    }

    TerminalStateRestorer(const TerminalStateRestorer&) = delete;
    TerminalStateRestorer& operator=(const TerminalStateRestorer&) = delete;

private:
    termios original_{};
    bool valid_ = false;
};

std::string zenity_program() {
    constexpr const char* candidates[] = {
        "/usr/bin/zenity",
        "/bin/zenity"
    };
    for(const char* candidate : candidates) {
        if(access(candidate, X_OK) == 0)
            return candidate;
    }
    throw std::runtime_error("zenity executable was not found");
}

int authenticate_user(
    const std::string& username,
    const std::string& process_name,
    const std::string& confdir,
    std::stop_token stop,
    KeepaliveState& keepalive,
    UserInteractionStateSink* state_sink,
    const UserContext& user,
    const UserInteractionRequest& request
) {
    // The handler normally restores echo itself. This guard also restores the
    // daemon's original terminal state if cancellation requires SIGKILL.
    TerminalStateRestorer terminal;
    UserActionKeepaliveGuard waiting_for_user(keepalive);
    const int status = vauth::uv::run_cancellable_program(
        "/proc/self/exe",
        {
            std::string(VAUTH_AUTH_HANDLER_COMMAND),
            username,
            process_name,
            confdir
        },
        stop,
        USER_ACTION_TIMEOUT,
        [state_sink, &user, &request](uint8_t raw_status) {
            switch(static_cast<vauth::uv::AuthHandlerStatus>(raw_status)) {
                case vauth::uv::AuthHandlerStatus::fingerprint_required:
                    publish_state(
                        state_sink,
                        user,
                        request,
                        UserInteractionState::fingerprint_required
                    );
                    break;
                case vauth::uv::AuthHandlerStatus::fingerprint_failed:
                    publish_state(
                        state_sink,
                        user,
                        request,
                        UserInteractionState::fingerprint_failed
                    );
                    break;
                case vauth::uv::AuthHandlerStatus::password_required:
                    publish_state(
                        state_sink,
                        user,
                        request,
                        UserInteractionState::password_required
                    );
                    break;
            }
        }
    );
    if(status < PAM_SUCCESS || status > PAM_INCOMPLETE)
        return PAM_SYSTEM_ERR;
    return status;
}

std::string_view presence_question(UserInteractionOperation operation) {
    switch(operation) {
        case UserInteractionOperation::make_credential:
            return "Authorize passkey creation?";
        case UserInteractionOperation::get_assertion:
            return "Authorize passkey usage?";
        case UserInteractionOperation::check_excluded_credential:
            return "Confirm user presence to continue passkey registration?";
    }
    return "Authorize passkey operation?";
}

bool collect_consent(
    std::string_view question,
    std::stop_token stop,
    KeepaliveState& keepalive
) {
    try {
        const std::string program = zenity_program();
        UserActionKeepaliveGuard waiting_for_user(keepalive);
        return vauth::uv::run_cancellable_program(
            program,
            {"--question", "--text=" + std::string(question)},
            stop,
            USER_ACTION_TIMEOUT
        ) == 0;
    } catch(const OperationCancelled&) {
        throw;
    } catch(const UserActionTimedOut&) {
        throw;
    } catch(const std::exception&) {
        return false;
    }
}

UserContext get_local_user_context() {
    const char* name = getlogin();
    if(name == nullptr)
        throw std::runtime_error("Unable to get current user name");

    const std::string username(name);
    long buffer_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    if(buffer_size < 0)
        buffer_size = 16384;

    std::vector<char> buffer(static_cast<std::size_t>(buffer_size));
    passwd account{};
    passwd* result = nullptr;
    const int rc = getpwnam_r(
        username.c_str(),
        &account,
        buffer.data(),
        buffer.size(),
        &result
    );
    if(rc != 0)
        throw std::system_error(rc, std::generic_category(), "getpwnam_r");
    if(result == nullptr)
        throw std::runtime_error("Unable to resolve current user name");
    if(
        static_cast<uintmax_t>(account.pw_uid) >
        std::numeric_limits<uint32_t>::max()
    ) {
        throw std::runtime_error("Current user UID is out of range");
    }

    return UserContext{
        .uid = static_cast<uint32_t>(account.pw_uid),
        .name = username,
        .session = std::nullopt
    };
}

}

PamUserInteraction::PamUserInteraction(
    std::string process_name,
    std::string configuration_directory,
    UserContextProvider* context_provider,
    UserInteractionStateSink* state_sink,
    bool allow_local_context
) :
    processName_(std::move(process_name)),
    configurationDirectory_(std::move(configuration_directory)),
    contextProvider_(context_provider),
    stateSink_(state_sink),
    allowLocalContext_(allow_local_context)
{}

UserContext PamUserInteraction::current_context(std::stop_token stop) {
    cancellation_point(stop);
    if(contextProvider_ != nullptr) {
        if(auto context = contextProvider_->current_context()) {
            cancellation_point(stop);
            return std::move(*context);
        }
    }
    if(!allowLocalContext_) {
        throw std::runtime_error(
            "No active vAuth user-interaction agent is registered"
        );
    }
    auto user = get_local_user_context();
    cancellation_point(stop);
    return user;
}

UserInteractionResult PamUserInteraction::request_presence(
    const UserContext& user,
    const UserInteractionRequest& request,
    std::stop_token stop,
    KeepaliveState& keepalive
) {
    InteractionScope interaction(stateSink_, user, request);
    const auto& active_request = interaction.request();
    publish_state(
        stateSink_,
        user,
        active_request,
        UserInteractionState::presence_required
    );
    try {
        const bool approved = collect_consent(
            presence_question(active_request.operation),
            stop,
            keepalive
        ) && context_is_still_current(contextProvider_, user);
        publish_state(
            stateSink_,
            user,
            active_request,
            approved
                ? UserInteractionState::presence_approved
                : UserInteractionState::presence_denied
        );
        return approved
            ? UserInteractionResult::approved
            : UserInteractionResult::denied;
    } catch(const OperationCancelled&) {
        publish_state(
            stateSink_, user, active_request, UserInteractionState::cancelled
        );
        throw;
    } catch(const UserActionTimedOut&) {
        publish_state(
            stateSink_, user, active_request, UserInteractionState::timed_out
        );
        throw;
    }
}

UserInteractionResult PamUserInteraction::request_verification(
    const UserContext& user,
    const UserInteractionRequest& request,
    std::stop_token stop,
    KeepaliveState& keepalive
) {
    InteractionScope interaction(stateSink_, user, request);
    const auto& active_request = interaction.request();
    publish_state(
        stateSink_,
        user,
        active_request,
        UserInteractionState::verification_started
    );
    try {
        const bool approved = authenticate_user(
            user.name,
            processName_,
            configurationDirectory_,
            stop,
            keepalive,
            stateSink_,
            user,
            active_request
        ) == PAM_SUCCESS && context_is_still_current(contextProvider_, user);
        publish_state(
            stateSink_,
            user,
            active_request,
            approved
                ? UserInteractionState::verification_succeeded
                : UserInteractionState::verification_failed
        );
        return approved
            ? UserInteractionResult::approved
            : UserInteractionResult::denied;
    } catch(const OperationCancelled&) {
        publish_state(
            stateSink_, user, active_request, UserInteractionState::cancelled
        );
        throw;
    } catch(const UserActionTimedOut&) {
        publish_state(
            stateSink_, user, active_request, UserInteractionState::timed_out
        );
        throw;
    }
}
