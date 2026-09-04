#pragma once

#include "uv/src/user_interaction.hpp"

#include <cstdint>
#include <memory>
#include <optional>

namespace vauth::dbus {

class AgentService final :
    public UserContextProvider,
    public UserInteractionChannel {
public:
    AgentService();
    ~AgentService() override;

    AgentService(const AgentService&) = delete;
    AgentService& operator=(const AgentService&) = delete;

    [[nodiscard]] std::optional<UserContext> current_context() override;
    [[nodiscard]] uint64_t begin_interaction(
        const UserContext& user,
        const UserInteractionRequest& request
    ) override;
    void publish_state(
        const UserContext& user,
        const UserInteractionRequest& request,
        UserInteractionState state
    ) override;
    void end_interaction(
        const UserContext& user,
        const UserInteractionRequest& request
    ) noexcept override;
    [[nodiscard]] UserInteractionResult wait_for_presence(
        const UserContext& user,
        const UserInteractionRequest& request,
        std::stop_token stop,
        std::chrono::steady_clock::duration timeout
    ) override;
    [[nodiscard]] bool cancellation_requested(
        const UserContext& user,
        const UserInteractionRequest& request
    ) const noexcept override;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}
