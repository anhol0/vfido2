#pragma once

#include "uv/src/user_context.hpp"
#include "uv/src/user_interaction.hpp"

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace vauth::dbus {

struct PendingInteraction {
    uint64_t requestId;
    UserContextBinding user;
    UserInteractionOperation operation;
    std::string relyingPartyId;
    std::optional<UserInteractionState> state;
};

class InteractionRegistry {
public:
    [[nodiscard]] uint64_t begin(
        const UserContext& user,
        UserInteractionOperation operation,
        std::string_view relying_party_id
    );
    void transition(
        const UserContext& user,
        uint64_t request_id,
        UserInteractionState state
    );
    [[nodiscard]] bool end(
        const UserContext& user,
        uint64_t request_id
    ) noexcept;
    void clear_for(const UserContext& user) noexcept;
    [[nodiscard]] std::optional<PendingInteraction> current() const;

private:
    mutable std::mutex mutex_;
    std::optional<PendingInteraction> current_;
    uint64_t nextRequestId_ = 1;
};

}
