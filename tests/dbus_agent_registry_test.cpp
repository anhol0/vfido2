#include "dbus/agent_registry.hpp"
#include "uv/src/user_interaction.hpp"

#include <iostream>
#include <stdexcept>
#include <string>

namespace {

#define CHECK(condition) do { \
    if(!(condition)) { \
        std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ \
                  << ": " #condition "\n"; \
        return false; \
    } \
} while(false)

vauth::dbus::AgentPeer peer(
    std::string bus_name = ":1.42",
    std::string session_id = "session-2"
) {
    return {
        .uid = 1000,
        .userName = "alice",
        .sessionId = std::move(session_id),
        .busName = std::move(bus_name)
    };
}

bool test_registration_lifetime() {
    vauth::dbus::AgentRegistry registry;

    const UserContext first = registry.register_agent(peer());
    CHECK(first.uid == 1000);
    CHECK(first.name == "alice");
    CHECK(first.session.has_value());
    CHECK(first.session->sessionId == "session-2");
    CHECK(first.session->interactionAgentId == ":1.42");
    CHECK(first.session->generation == 1);
    CHECK(registry.is_current(first));

    const UserContext repeated = registry.register_agent(peer());
    CHECK(repeated.name == first.name);
    CHECK(repeated.binding() == first.binding());

    bool competing_rejected = false;
    try {
        static_cast<void>(registry.register_agent(peer(":1.43")));
    } catch(const std::runtime_error&) {
        competing_rejected = true;
    }
    CHECK(competing_rejected);
    CHECK(!registry.unregister_agent(":1.43"));
    CHECK(registry.unregister_agent(":1.42"));
    CHECK(!registry.current_context().has_value());
    CHECK(!registry.is_current(first));

    const UserContext second = registry.register_agent(peer(":1.43"));
    CHECK(second.session->generation == 2);
    CHECK(registry.is_current(second));
    CHECK(!registry.is_current(first));
    return true;
}

bool test_invalid_identity_rejected() {
    const auto rejected = [](vauth::dbus::AgentPeer invalid_peer) {
        vauth::dbus::AgentRegistry registry;
        try {
            static_cast<void>(registry.register_agent(
                std::move(invalid_peer)
            ));
        } catch(const std::invalid_argument&) {
            return true;
        }
        return false;
    };

    auto no_name = peer();
    no_name.userName.clear();
    CHECK(rejected(std::move(no_name)));

    auto no_session = peer();
    no_session.sessionId.clear();
    CHECK(rejected(std::move(no_session)));

    auto no_bus_name = peer();
    no_bus_name.busName.clear();
    CHECK(rejected(std::move(no_bus_name)));

    auto well_known_name = peer();
    well_known_name.busName = "org.example.Agent";
    CHECK(rejected(std::move(well_known_name)));
    return true;
}

bool test_state_names() {
    CHECK(
        user_interaction_operation_name(
            UserInteractionOperation::make_credential
        ) == "make_credential"
    );
    CHECK(
        user_interaction_state_name(
            UserInteractionState::fingerprint_failed
        ) == "fingerprint_failed"
    );
    CHECK(
        user_interaction_state_name(
            UserInteractionState::password_required
        ) == "password_required"
    );
    return true;
}

}

int main() {
    const bool success =
        test_registration_lifetime() &&
        test_invalid_identity_rejected() &&
        test_state_names();
    if(success)
        std::cout << "3/3 D-Bus agent registry tests passed\n";
    return success ? 0 : 1;
}
