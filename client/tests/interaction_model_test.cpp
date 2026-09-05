#include "interaction_model.hpp"
#include "test_runner.hpp"

#include <iostream>

namespace {

#define CHECK(condition) do { \
    if(!(condition)) { \
        std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ \
                  << ": " #condition "\n"; \
        return false; \
    } \
} while(false)

vauth::client::InteractionEvent event(
    vauth::client::InteractionState state,
    uint64_t generation = 7,
    uint64_t request_id = 42
) {
    return {
        .generation = generation,
        .requestId = request_id,
        .state = state,
        .operation = "make_credential",
        .relyingPartyId = "example.com"
    };
}

bool test_state_parser_is_strict() {
    using vauth::client::InteractionState;
    CHECK(
        vauth::client::parse_interaction_state("password_required") ==
        InteractionState::password_required
    );
    CHECK(!vauth::client::parse_interaction_state("password-required"));
    CHECK(!vauth::client::parse_interaction_state(""));
    return true;
}

bool test_tracker_rejects_stale_and_foreign_events() {
    using vauth::client::InteractionState;
    vauth::client::InteractionTracker tracker(7);

    CHECK(!tracker.accept(event(InteractionState::presence_required, 6)));
    CHECK(!tracker.accept(event(InteractionState::presence_required, 7, 0)));
    CHECK(tracker.accept(event(InteractionState::presence_required)));
    CHECK(tracker.is_active(42));
    CHECK(!tracker.accept(event(InteractionState::password_required, 7, 43)));
    CHECK(tracker.accept(event(InteractionState::presence_denied)));
    CHECK(!tracker.is_active(42));
    CHECK(!tracker.accept(event(InteractionState::presence_approved)));
    return true;
}

bool test_tracker_accepts_verification_sequence() {
    using vauth::client::InteractionState;
    vauth::client::InteractionTracker tracker(7);

    CHECK(tracker.accept(event(InteractionState::verification_started)));
    CHECK(tracker.accept(event(InteractionState::fingerprint_required)));
    CHECK(tracker.accept(event(InteractionState::fingerprint_failed)));
    CHECK(tracker.accept(event(InteractionState::password_required)));
    CHECK(tracker.accept(event(InteractionState::verification_succeeded)));
    CHECK(!tracker.is_active(42));
    return true;
}

bool test_ui_model_maps_presence_and_password() {
    using vauth::client::InteractionState;
    using vauth::client::ViewKind;
    vauth::client::UiModel model;

    const auto presence = model.apply(
        event(InteractionState::presence_required)
    );
    CHECK(presence.view == ViewKind::presence);
    CHECK(presence.title == "Create a passkey?");
    CHECK(presence.relyingPartyId == "example.com");
    CHECK(!presence.terminal);

    const auto password = model.apply(
        event(InteractionState::password_required)
    );
    CHECK(password.view == ViewKind::password);
    CHECK(!password.terminal);
    return true;
}

bool test_ui_model_maps_terminal_states() {
    using vauth::client::AnimationKind;
    using vauth::client::InteractionState;
    using vauth::client::ViewKind;
    vauth::client::UiModel model;

    static_cast<void>(model.apply(
        event(InteractionState::fingerprint_required)
    ));
    const auto success = model.apply(
        event(InteractionState::verification_succeeded)
    );
    CHECK(success.view == ViewKind::fingerprint);
    CHECK(success.animation == AnimationKind::success);
    CHECK(success.terminal);

    const auto timeout = model.apply(event(InteractionState::timed_out));
    CHECK(timeout.view == ViewKind::status);
    CHECK(timeout.title == "Timed out");
    CHECK(timeout.terminal);
    return true;
}

bool test_password_fallback_failure_uses_failure_animation() {
    using vauth::client::AnimationKind;
    using vauth::client::InteractionState;
    using vauth::client::ViewKind;
    vauth::client::UiModel model;

    static_cast<void>(model.apply(
        event(InteractionState::verification_started)
    ));
    static_cast<void>(model.apply(
        event(InteractionState::password_required)
    ));
    const auto failure = model.apply(
        event(InteractionState::verification_failed)
    );

    CHECK(failure.view == ViewKind::fingerprint);
    CHECK(failure.animation == AnimationKind::failure);
    CHECK(failure.title == "Verification failed");
    CHECK(failure.terminal);
    return true;
}

} // namespace

int main() {
    test_support::Runner runner;
    runner.run("state parser is strict", test_state_parser_is_strict);
    runner.run(
        "tracker rejects stale and foreign events",
        test_tracker_rejects_stale_and_foreign_events
    );
    runner.run(
        "tracker accepts verification sequence",
        test_tracker_accepts_verification_sequence
    );
    runner.run(
        "UI model maps presence and password",
        test_ui_model_maps_presence_and_password
    );
    runner.run(
        "UI model maps terminal states",
        test_ui_model_maps_terminal_states
    );
    runner.run(
        "password fallback failure uses failure animation",
        test_password_fallback_failure_uses_failure_animation
    );
    return runner.finish();
}
