#pragma once

#include <cstdint>
#include <stop_token>
#include <string>
#include <string_view>

class KeepaliveState;

struct UserIdentity {
    uint32_t uid;
    std::string name;
};

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
    [[nodiscard]] virtual UserIdentity current_user(
        std::stop_token stop
    ) = 0;
    [[nodiscard]] virtual UserInteractionResult request_presence(
        const UserIdentity& user,
        const UserInteractionRequest& request,
        std::stop_token stop,
        KeepaliveState& keepalive
    ) = 0;
    [[nodiscard]] virtual UserInteractionResult request_verification(
        const UserIdentity& user,
        const UserInteractionRequest& request,
        std::stop_token stop,
        KeepaliveState& keepalive
    ) = 0;
};
