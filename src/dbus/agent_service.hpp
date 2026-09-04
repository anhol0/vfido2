#pragma once

#include "uv/src/user_interaction.hpp"

#include <cstdint>
#include <memory>
#include <optional>

namespace vauth::dbus {

class AgentService final :
    public UserContextProvider,
    public UserInteractionStateSink {
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

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}
