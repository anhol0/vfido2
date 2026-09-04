#include "dbus/agent_registry.hpp"
#include "dbus/interaction_registry.hpp"
#include "uv/src/user_interaction.hpp"

#include <chrono>
#include <iostream>
#include <stop_token>
#include <stdexcept>
#include <string>
#include <thread>

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

bool test_interaction_lifecycle() {
    vauth::dbus::AgentRegistry agents;
    vauth::dbus::InteractionRegistry interactions;
    const UserContext user = agents.register_agent(peer());

    const uint64_t first_id = interactions.begin(
        user,
        UserInteractionOperation::make_credential,
        "example.com"
    );
    CHECK(first_id != 0);
    auto pending = interactions.current();
    CHECK(pending.has_value());
    CHECK(pending->requestId == first_id);
    CHECK(pending->user == user.binding());
    CHECK(pending->operation == UserInteractionOperation::make_credential);
    CHECK(pending->relyingPartyId == "example.com");
    CHECK(!pending->state.has_value());

    bool competing_rejected = false;
    try {
        static_cast<void>(interactions.begin(
            user,
            UserInteractionOperation::get_assertion,
            "example.com"
        ));
    } catch(const std::runtime_error&) {
        competing_rejected = true;
    }
    CHECK(competing_rejected);

    CHECK(interactions.transition(
        user,
        first_id,
        UserInteractionState::verification_started
    ));
    CHECK(interactions.transition(
        user,
        first_id,
        UserInteractionState::fingerprint_required
    ));
    CHECK(interactions.transition(
        user,
        first_id,
        UserInteractionState::fingerprint_failed
    ));
    CHECK(interactions.transition(
        user,
        first_id,
        UserInteractionState::password_required
    ));
    CHECK(interactions.transition(
        user,
        first_id,
        UserInteractionState::verification_succeeded
    ));
    CHECK(!interactions.current().has_value());

    bool stale_rejected = false;
    try {
        static_cast<void>(interactions.transition(
            user,
            first_id,
            UserInteractionState::verification_failed
        ));
    } catch(const std::runtime_error&) {
        stale_rejected = true;
    }
    CHECK(stale_rejected);

    const uint64_t second_id = interactions.begin(
        user,
        UserInteractionOperation::get_assertion,
        "example.com"
    );
    CHECK(second_id > first_id);
    CHECK(interactions.end(user, second_id));
    CHECK(!interactions.current().has_value());
    return true;
}

bool test_interaction_transition_validation() {
    vauth::dbus::AgentRegistry agents;
    vauth::dbus::InteractionRegistry interactions;
    const UserContext user = agents.register_agent(peer());
    const uint64_t request_id = interactions.begin(
        user,
        UserInteractionOperation::check_excluded_credential,
        "example.com"
    );

    CHECK(interactions.transition(
        user,
        request_id,
        UserInteractionState::presence_required
    ));
    bool invalid_rejected = false;
    try {
        static_cast<void>(interactions.transition(
            user,
            request_id,
            UserInteractionState::fingerprint_required
        ));
    } catch(const std::logic_error&) {
        invalid_rejected = true;
    }
    CHECK(invalid_rejected);
    CHECK(
        interactions.current()->state ==
        UserInteractionState::presence_required
    );

    UserContext wrong_user = user;
    wrong_user.uid = 1001;
    CHECK(!interactions.end(wrong_user, request_id));
    interactions.clear_for(wrong_user);
    CHECK(interactions.current().has_value());

    CHECK(interactions.transition(
        user,
        request_id,
        UserInteractionState::presence_denied
    ));
    CHECK(!interactions.current().has_value());
    return true;
}

bool test_presence_responses_and_cancellation() {
    vauth::dbus::AgentRegistry agents;
    vauth::dbus::InteractionRegistry interactions;
    const UserContext user = agents.register_agent(peer());

    const uint64_t presence_id = interactions.begin(
        user,
        UserInteractionOperation::make_credential,
        "example.com"
    );
    CHECK(interactions.transition(
        user,
        presence_id,
        UserInteractionState::presence_required
    ));
    std::jthread responder([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        interactions.respond_to_presence(user, presence_id, true);
    });
    std::stop_source stop;
    CHECK(
        interactions.wait_for_presence(
            user,
            presence_id,
            stop.get_token(),
            std::chrono::seconds(1)
        ) == vauth::dbus::PresenceWaitResult::approved
    );
    responder.join();

    bool duplicate_rejected = false;
    try {
        interactions.respond_to_presence(user, presence_id, false);
    } catch(const std::runtime_error&) {
        duplicate_rejected = true;
    }
    CHECK(duplicate_rejected);
    CHECK(interactions.transition(
        user,
        presence_id,
        UserInteractionState::presence_approved
    ));

    const uint64_t verification_id = interactions.begin(
        user,
        UserInteractionOperation::get_assertion,
        "example.com"
    );
    CHECK(interactions.transition(
        user,
        verification_id,
        UserInteractionState::verification_started
    ));
    CHECK(!interactions.cancellation_requested(user, verification_id));
    interactions.request_cancel(user, verification_id);
    CHECK(interactions.cancellation_requested(user, verification_id));
    CHECK(
        interactions.wait_for_presence(
            user,
            verification_id,
            stop.get_token(),
            std::chrono::seconds(1)
        ) == vauth::dbus::PresenceWaitResult::client_cancelled
    );
    CHECK(!interactions.transition(
        user,
        verification_id,
        UserInteractionState::fingerprint_required
    ));
    CHECK(interactions.transition(
        user,
        verification_id,
        UserInteractionState::cancelled
    ));

    const uint64_t timeout_id = interactions.begin(
        user,
        UserInteractionOperation::check_excluded_credential,
        "example.com"
    );
    CHECK(interactions.transition(
        user,
        timeout_id,
        UserInteractionState::presence_required
    ));
    CHECK(
        interactions.wait_for_presence(
            user,
            timeout_id,
            stop.get_token(),
            std::chrono::milliseconds(1)
        ) == vauth::dbus::PresenceWaitResult::timed_out
    );
    bool late_response_rejected = false;
    try {
        interactions.respond_to_presence(user, timeout_id, true);
    } catch(const std::runtime_error&) {
        late_response_rejected = true;
    }
    CHECK(late_response_rejected);
    CHECK(interactions.transition(
        user,
        timeout_id,
        UserInteractionState::timed_out
    ));
    return true;
}

}

int main() {
    const bool success =
        test_registration_lifetime() &&
        test_invalid_identity_rejected() &&
        test_state_names() &&
        test_interaction_lifecycle() &&
        test_interaction_transition_validation() &&
        test_presence_responses_and_cancellation();
    if(success)
        std::cout << "6/6 D-Bus registry tests passed\n";
    return success ? 0 : 1;
}
