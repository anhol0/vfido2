#pragma once

#include "user_context.hpp"

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
};

enum class UserInteractionResult {
    approved,
    denied
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
