#include "auth.hpp"

#include "auth_handler.hpp"
#include "auth_handler_status.hpp"
#include "cancellable_process.hpp"
#include "cancellation.hpp"
#include "keepalive.hpp"

#include <chrono>
#include <security/_pam_types.h>
#include <string>
#include <utility>

namespace {

constexpr auto USER_ACTION_TIMEOUT = std::chrono::seconds(30);

void publish_state(
    UserInteractionChannel& channel,
    const UserContext& user,
    const UserInteractionRequest& request,
    UserInteractionState state
) {
    channel.publish_state(user, request, state);
}

bool context_is_still_current(
    UserContextProvider& provider,
    const UserContext& user
) {
    const auto current = provider.current_context();
    return current && current->binding() == user.binding();
}

class InteractionScope {
public:
    InteractionScope(
        UserInteractionChannel& channel,
        const UserContext& user,
        const UserInteractionRequest& request
    ) : channel_(channel), user_(user), request_(request) {
        request_.requestId = channel_.begin_interaction(user_, request_);
        if(request_.requestId == 0)
            throw UserInteractionUnavailable{};
    }

    ~InteractionScope() {
        channel_.end_interaction(user_, request_);
    }

    InteractionScope(const InteractionScope&) = delete;
    InteractionScope& operator=(const InteractionScope&) = delete;

    [[nodiscard]] const UserInteractionRequest& request() const noexcept {
        return request_;
    }

private:
    UserInteractionChannel& channel_;
    const UserContext& user_;
    UserInteractionRequest request_;
};

int authenticate_user(
    const std::string& username,
    const std::string& process_name,
    const std::string& confdir,
    std::stop_token stop,
    KeepaliveState& keepalive,
    UserInteractionChannel& interaction_channel,
    const UserContext& user,
    const UserInteractionRequest& request
) {
    UserActionKeepaliveGuard waiting_for_user(keepalive);
    const auto deadline = std::chrono::steady_clock::now() +
        USER_ACTION_TIMEOUT;
    auto password_callback = [
        &interaction_channel,
        &user,
        &request,
        stop,
        deadline
    ] {
        const auto now = std::chrono::steady_clock::now();
        if(now >= deadline)
            throw UserActionTimedOut{};
        return interaction_channel.wait_for_password(
            user,
            request,
            stop,
            deadline - now
        );
    };
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
        [&interaction_channel, &user, &request](uint8_t raw_status) {
            switch(static_cast<vauth::uv::AuthHandlerStatus>(raw_status)) {
                case vauth::uv::AuthHandlerStatus::fingerprint_required:
                    publish_state(
                        interaction_channel,
                        user,
                        request,
                        UserInteractionState::fingerprint_required
                    );
                    break;
                case vauth::uv::AuthHandlerStatus::fingerprint_failed:
                    publish_state(
                        interaction_channel,
                        user,
                        request,
                        UserInteractionState::fingerprint_failed
                    );
                    break;
                case vauth::uv::AuthHandlerStatus::password_required:
                    publish_state(
                        interaction_channel,
                        user,
                        request,
                        UserInteractionState::password_required
                    );
                    break;
            }
        },
        [&interaction_channel, &user, &request] {
            return interaction_channel.cancellation_requested(user, request);
        },
        password_callback
    );
    if(status < PAM_SUCCESS || status > PAM_INCOMPLETE)
        return PAM_SYSTEM_ERR;
    return status;
}

}

PamUserInteraction::PamUserInteraction(
    std::string process_name,
    std::string configuration_directory,
    UserContextProvider& context_provider,
    UserInteractionChannel& interaction_channel
) :
    processName_(std::move(process_name)),
    configurationDirectory_(std::move(configuration_directory)),
    contextProvider_(context_provider),
    interactionChannel_(interaction_channel)
{}

UserContext PamUserInteraction::current_context(std::stop_token stop) {
    cancellation_point(stop);
    if(auto context = contextProvider_.current_context()) {
        cancellation_point(stop);
        return std::move(*context);
    }
    throw UserInteractionUnavailable{};
}

UserInteractionResult PamUserInteraction::request_presence(
    const UserContext& user,
    const UserInteractionRequest& request,
    std::stop_token stop,
    KeepaliveState& keepalive
) {
    InteractionScope interaction(interactionChannel_, user, request);
    const auto& active_request = interaction.request();
    publish_state(
        interactionChannel_,
        user,
        active_request,
        UserInteractionState::presence_required
    );
    try {
        UserActionKeepaliveGuard waiting_for_user(keepalive);
        const UserInteractionResult response =
            interactionChannel_.wait_for_presence(
                user,
                active_request,
                stop,
                USER_ACTION_TIMEOUT
            );
        if(response == UserInteractionResult::cancelled) {
            publish_state(
                interactionChannel_, user, active_request,
                UserInteractionState::cancelled
            );
            return UserInteractionResult::cancelled;
        }
        const bool approved =
            response == UserInteractionResult::approved &&
            context_is_still_current(contextProvider_, user);
        publish_state(
            interactionChannel_,
            user,
            active_request,
            approved
                ? UserInteractionState::presence_approved
                : UserInteractionState::presence_denied
        );
        return approved
            ? UserInteractionResult::approved
            : UserInteractionResult::denied;
    } catch(const UserInteractionCancelled&) {
        publish_state(
            interactionChannel_, user, active_request,
            UserInteractionState::cancelled
        );
        return UserInteractionResult::cancelled;
    } catch(const OperationCancelled&) {
        publish_state(
            interactionChannel_, user, active_request,
            UserInteractionState::cancelled
        );
        throw;
    } catch(const UserActionTimedOut&) {
        publish_state(
            interactionChannel_, user, active_request,
            UserInteractionState::timed_out
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
    InteractionScope interaction(interactionChannel_, user, request);
    const auto& active_request = interaction.request();
    publish_state(
        interactionChannel_,
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
            interactionChannel_,
            user,
            active_request
        ) == PAM_SUCCESS && context_is_still_current(contextProvider_, user);
        publish_state(
            interactionChannel_,
            user,
            active_request,
            approved
                ? UserInteractionState::verification_succeeded
                : UserInteractionState::verification_failed
        );
        return approved
            ? UserInteractionResult::approved
            : UserInteractionResult::denied;
    } catch(const UserInteractionCancelled&) {
        publish_state(
            interactionChannel_, user, active_request,
            UserInteractionState::cancelled
        );
        return UserInteractionResult::cancelled;
    } catch(const OperationCancelled&) {
        publish_state(
            interactionChannel_, user, active_request,
            UserInteractionState::cancelled
        );
        throw;
    } catch(const UserActionTimedOut&) {
        publish_state(
            interactionChannel_, user, active_request,
            UserInteractionState::timed_out
        );
        throw;
    }
}
