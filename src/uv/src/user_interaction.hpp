#pragma once

#include "user_context.hpp"

#include <cstdint>
#include <optional>
#include <stop_token>
#include <string_view>

class KeepaliveState;

enum class UserInteractionOperation {
    make_credential,
    get_assertion,
    check_excluded_credential
};

struct UserInteractionRequest {
    UserInteractionOperation operation;
    std::string_view relyingPartyId;
    uint64_t requestId = 0;
};

enum class UserInteractionResult {
    approved,
    denied
};

enum class UserInteractionState {
    presence_required,
    presence_approved,
    presence_denied,
    verification_started,
    fingerprint_required,
    fingerprint_failed,
    password_required,
    verification_succeeded,
    verification_failed,
    cancelled,
    timed_out
};

[[nodiscard]] constexpr std::string_view user_interaction_operation_name(
    UserInteractionOperation operation
) noexcept {
    switch(operation) {
        case UserInteractionOperation::make_credential:
            return "make_credential";
        case UserInteractionOperation::get_assertion:
            return "get_assertion";
        case UserInteractionOperation::check_excluded_credential:
            return "check_excluded_credential";
    }
    return "unknown";
}

[[nodiscard]] constexpr std::string_view user_interaction_state_name(
    UserInteractionState state
) noexcept {
    switch(state) {
        case UserInteractionState::presence_required:
            return "presence_required";
        case UserInteractionState::presence_approved:
            return "presence_approved";
        case UserInteractionState::presence_denied:
            return "presence_denied";
        case UserInteractionState::verification_started:
            return "verification_started";
        case UserInteractionState::fingerprint_required:
            return "fingerprint_required";
        case UserInteractionState::fingerprint_failed:
            return "fingerprint_failed";
        case UserInteractionState::password_required:
            return "password_required";
        case UserInteractionState::verification_succeeded:
            return "verification_succeeded";
        case UserInteractionState::verification_failed:
            return "verification_failed";
        case UserInteractionState::cancelled:
            return "cancelled";
        case UserInteractionState::timed_out:
            return "timed_out";
    }
    return "unknown";
}

class UserContextProvider {
public:
    virtual ~UserContextProvider() = default;
    [[nodiscard]] virtual std::optional<UserContext> current_context() = 0;
};

class UserInteractionStateSink {
public:
    virtual ~UserInteractionStateSink() = default;
    [[nodiscard]] virtual uint64_t begin_interaction(
        const UserContext& user,
        const UserInteractionRequest& request
    ) = 0;
    virtual void publish_state(
        const UserContext& user,
        const UserInteractionRequest& request,
        UserInteractionState state
    ) = 0;
    virtual void end_interaction(
        const UserContext& user,
        const UserInteractionRequest& request
    ) noexcept = 0;
};

class UserInteraction {
public:
    virtual ~UserInteraction() = default;

    // Implementations report cancellation and deadline expiry with the
    // existing OperationCancelled and UserActionTimedOut exceptions.
    [[nodiscard]] virtual UserContext current_context(
        std::stop_token stop
    ) = 0;
    [[nodiscard]] virtual UserInteractionResult request_presence(
        const UserContext& user,
        const UserInteractionRequest& request,
        std::stop_token stop,
        KeepaliveState& keepalive
    ) = 0;
    [[nodiscard]] virtual UserInteractionResult request_verification(
        const UserContext& user,
        const UserInteractionRequest& request,
        std::stop_token stop,
        KeepaliveState& keepalive
    ) = 0;
};
