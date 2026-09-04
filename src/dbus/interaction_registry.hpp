#pragma once

#include "uv/src/user_context.hpp"
#include "uv/src/user_interaction.hpp"
#include "uv/src/sensitive_bytes.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <stop_token>

namespace vauth::dbus {

struct PendingInteraction {
    uint64_t requestId;
    UserContextBinding user;
    UserInteractionOperation operation;
    std::string relyingPartyId;
    std::optional<UserInteractionState> state;
    std::optional<bool> presenceResponse;
    bool passwordSubmitted = false;
    bool cancelRequested = false;
    bool responseClosed = false;
};

enum class PresenceWaitResult {
    approved,
    denied,
    client_cancelled,
    platform_cancelled,
    timed_out,
    invalidated
};

enum class PasswordWaitStatus {
    provided,
    client_cancelled,
    platform_cancelled,
    timed_out,
    invalidated
};

struct PasswordWaitResult {
    PasswordWaitStatus status;
    vauth::uv::SensitiveBytes password;
};

class InteractionRegistry {
public:
    [[nodiscard]] uint64_t begin(
        const UserContext& user,
        UserInteractionOperation operation,
        std::string_view relying_party_id
    );
    [[nodiscard]] bool transition(
        const UserContext& user,
        uint64_t request_id,
        UserInteractionState state
    );
    void respond_to_presence(
        const UserContext& user,
        uint64_t request_id,
        bool approved
    );
    void submit_password(
        const UserContext& user,
        uint64_t request_id,
        vauth::uv::SensitiveBytes password
    );
    void request_cancel(
        const UserContext& user,
        uint64_t request_id
    );
    [[nodiscard]] PresenceWaitResult wait_for_presence(
        const UserContext& user,
        uint64_t request_id,
        std::stop_token stop,
        std::chrono::steady_clock::duration timeout
    );
    [[nodiscard]] PasswordWaitResult wait_for_password(
        const UserContext& user,
        uint64_t request_id,
        std::stop_token stop,
        std::chrono::steady_clock::duration timeout
    );
    [[nodiscard]] bool cancellation_requested(
        const UserContext& user,
        uint64_t request_id
    ) const noexcept;
    [[nodiscard]] bool end(
        const UserContext& user,
        uint64_t request_id
    ) noexcept;
    void clear_for(const UserContext& user) noexcept;
    [[nodiscard]] std::optional<PendingInteraction> current() const;

private:
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    std::optional<PendingInteraction> current_;
    std::optional<vauth::uv::SensitiveBytes> passwordResponse_;
    uint64_t nextRequestId_ = 1;
};

}
