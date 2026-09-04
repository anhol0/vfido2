#pragma once

#include "uv/src/user_context.hpp"

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace vauth::dbus {

struct AgentPeer {
    uint32_t uid;
    std::string userName;
    std::string sessionId;
    std::string busName;
};

// Holds the single active local UI agent. The D-Bus adapter validates peer and
// session credentials before inserting them here.
class AgentRegistry {
public:
    [[nodiscard]] UserContext register_agent(AgentPeer peer);
    [[nodiscard]] bool unregister_agent(std::string_view bus_name);
    [[nodiscard]] std::optional<UserContext> current_context() const;
    [[nodiscard]] bool is_current(const UserContext& context) const;

private:
    mutable std::mutex mutex_;
    std::optional<UserContext> current_;
    uint64_t nextGeneration_ = 1;
};

}
