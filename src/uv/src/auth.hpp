#pragma once

#include "user_interaction.hpp"

#include <stop_token>
#include <string>

class PamUserInteraction final : public UserInteraction {
public:
    PamUserInteraction(
        std::string process_name,
        std::string configuration_directory
    );

    [[nodiscard]] UserContext current_context(
        std::stop_token stop
    ) override;
    [[nodiscard]] UserInteractionResult request_presence(
        const UserContext& user,
        const UserInteractionRequest& request,
        std::stop_token stop,
        KeepaliveState& keepalive
    ) override;
    [[nodiscard]] UserInteractionResult request_verification(
        const UserContext& user,
        const UserInteractionRequest& request,
        std::stop_token stop,
        KeepaliveState& keepalive
    ) override;

private:
    std::string processName_;
    std::string configurationDirectory_;
};
