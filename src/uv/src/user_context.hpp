#pragma once

#include <cstdint>
#include <optional>
#include <string>

// Identifies one registration of a UI agent in a local login session. The IPC
// adapter must derive these fields from trusted peer and session credentials,
// never from identity values asserted by the UI.
struct UserSessionContext {
    std::string sessionId;
    std::string interactionAgentId;
    uint64_t generation;

    bool operator==(const UserSessionContext&) const = default;
};

struct UserContextBinding {
    uint32_t uid;
    std::optional<UserSessionContext> session;

    bool operator==(const UserContextBinding&) const = default;
};

// Stable identity and session snapshot for one CTAP ceremony.
struct UserContext {
    uint32_t uid;
    std::string name;
    std::optional<UserSessionContext> session;

    [[nodiscard]] UserContextBinding binding() const {
        return {
            .uid = uid,
            .session = session
        };
    }
};
