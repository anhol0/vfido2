#include "interaction_model.hpp"

namespace vauth::client {

std::optional<InteractionState> parse_interaction_state(
    std::string_view state
) noexcept {
    if(state == "presence_required")
        return InteractionState::presence_required;
    if(state == "presence_approved")
        return InteractionState::presence_approved;
    if(state == "presence_denied")
        return InteractionState::presence_denied;
    if(state == "verification_started")
        return InteractionState::verification_started;
    if(state == "fingerprint_required")
        return InteractionState::fingerprint_required;
    if(state == "fingerprint_failed")
        return InteractionState::fingerprint_failed;
    if(state == "password_required")
        return InteractionState::password_required;
    if(state == "verification_succeeded")
        return InteractionState::verification_succeeded;
    if(state == "verification_failed")
        return InteractionState::verification_failed;
    if(state == "cancelled")
        return InteractionState::cancelled;
    if(state == "timed_out")
        return InteractionState::timed_out;
    return std::nullopt;
}

bool is_terminal(InteractionState state) noexcept {
    switch(state) {
        case InteractionState::presence_approved:
        case InteractionState::presence_denied:
        case InteractionState::verification_succeeded:
        case InteractionState::verification_failed:
        case InteractionState::cancelled:
        case InteractionState::timed_out:
            return true;
        case InteractionState::presence_required:
        case InteractionState::verification_started:
        case InteractionState::fingerprint_required:
        case InteractionState::fingerprint_failed:
        case InteractionState::password_required:
            return false;
    }
    return true;
}

InteractionTracker::InteractionTracker(uint64_t generation) noexcept
    : generation_(generation) {}

bool InteractionTracker::accept(const InteractionEvent& event) noexcept {
    if(event.generation != generation_ || event.requestId == 0)
        return false;

    const bool starts_interaction =
        event.state == InteractionState::presence_required ||
        event.state == InteractionState::verification_started;
    if(starts_interaction) {
        if(activeRequestId_ && *activeRequestId_ != event.requestId)
            return false;
        activeRequestId_ = event.requestId;
    } else if(!activeRequestId_ || *activeRequestId_ != event.requestId) {
        return false;
    }

    if(is_terminal(event.state))
        activeRequestId_.reset();
    return true;
}

bool InteractionTracker::is_active(uint64_t request_id) const noexcept {
    return activeRequestId_ && *activeRequestId_ == request_id;
}

namespace {

std::string operation_title(std::string_view operation) {
    if(operation == "make_credential")
        return "Create a passkey?";
    if(operation == "get_assertion")
        return "Use your passkey?";
    if(operation == "check_excluded_credential")
        return "Confirm your presence";
    return "Authorize passkey operation?";
}

} // namespace

UiPresentation UiModel::apply(const InteractionEvent& event) {
    UiPresentation result;
    result.relyingPartyId = event.relyingPartyId;
    result.terminal = is_terminal(event.state);

    switch(event.state) {
        case InteractionState::presence_required:
            result.view = ViewKind::presence;
            result.title = operation_title(event.operation);
            result.message = "Approve only if you initiated this request.";
            break;
        case InteractionState::presence_approved:
            result.view = ViewKind::status;
            result.title = "Approved";
            result.message = "The passkey operation was approved.";
            break;
        case InteractionState::presence_denied:
            result.view = ViewKind::status;
            result.title = "Denied";
            result.message = "The passkey operation was denied.";
            break;
        case InteractionState::verification_started:
        case InteractionState::fingerprint_required:
            result.view = ViewKind::fingerprint;
            result.animation = AnimationKind::waiting;
            result.title = "Verify your identity";
            result.message = "Touch the fingerprint reader to authorize.";
            break;
        case InteractionState::fingerprint_failed:
            result.view = ViewKind::fingerprint;
            result.animation = AnimationKind::failure;
            result.title = "Fingerprint not recognized";
            result.message = "Try again or use your password.";
            break;
        case InteractionState::password_required:
            result.view = ViewKind::password;
            result.title = "Enter your password";
            result.message = "Use your local account password to authorize.";
            break;
        case InteractionState::verification_succeeded:
            result.view = currentView_ == ViewKind::fingerprint
                ? ViewKind::fingerprint
                : ViewKind::status;
            result.animation = currentView_ == ViewKind::fingerprint
                ? AnimationKind::success
                : AnimationKind::none;
            result.title = "Identity verified";
            result.message = "The passkey operation can continue.";
            break;
        case InteractionState::verification_failed:
            result.view = ViewKind::status;
            result.title = "Verification failed";
            result.message = "Your identity could not be verified.";
            break;
        case InteractionState::cancelled:
            result.view = ViewKind::status;
            result.title = "Cancelled";
            result.message = "The passkey operation was cancelled.";
            break;
        case InteractionState::timed_out:
            result.view = ViewKind::status;
            result.title = "Timed out";
            result.message = "The passkey operation took too long.";
            break;
    }

    currentView_ = result.view;
    return result;
}

} // namespace vauth::client
