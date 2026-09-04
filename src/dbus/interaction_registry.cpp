#include "interaction_registry.hpp"

#include <chrono>
#include <limits>
#include <stdexcept>

namespace vauth::dbus {
namespace {

bool same_user(
    const UserContextBinding& binding,
    const UserContext& context
) noexcept {
    if(binding.uid != context.uid)
        return false;
    if(binding.session.has_value() != context.session.has_value())
        return false;
    if(!binding.session)
        return true;
    return *binding.session == *context.session;
}

bool is_terminal(UserInteractionState state) noexcept {
    switch(state) {
        case UserInteractionState::presence_approved:
        case UserInteractionState::presence_denied:
        case UserInteractionState::verification_succeeded:
        case UserInteractionState::verification_failed:
        case UserInteractionState::cancelled:
        case UserInteractionState::timed_out:
            return true;
        case UserInteractionState::presence_required:
        case UserInteractionState::verification_started:
        case UserInteractionState::fingerprint_required:
        case UserInteractionState::fingerprint_failed:
        case UserInteractionState::password_required:
            return false;
    }
    return true;
}

bool is_verification_progress(UserInteractionState state) noexcept {
    switch(state) {
        case UserInteractionState::verification_started:
        case UserInteractionState::fingerprint_required:
        case UserInteractionState::fingerprint_failed:
        case UserInteractionState::password_required:
            return true;
        case UserInteractionState::presence_required:
        case UserInteractionState::presence_approved:
        case UserInteractionState::presence_denied:
        case UserInteractionState::verification_succeeded:
        case UserInteractionState::verification_failed:
        case UserInteractionState::cancelled:
        case UserInteractionState::timed_out:
            return false;
    }
    return false;
}

bool valid_transition(
    std::optional<UserInteractionState> previous,
    UserInteractionState next
) noexcept {
    if(!previous) {
        return
            next == UserInteractionState::presence_required ||
            next == UserInteractionState::verification_started;
    }
    if(*previous == UserInteractionState::presence_required) {
        return
            next == UserInteractionState::presence_approved ||
            next == UserInteractionState::presence_denied ||
            next == UserInteractionState::cancelled ||
            next == UserInteractionState::timed_out;
    }
    if(is_verification_progress(*previous)) {
        return
            is_verification_progress(next) ||
            next == UserInteractionState::verification_succeeded ||
            next == UserInteractionState::verification_failed ||
            next == UserInteractionState::cancelled ||
            next == UserInteractionState::timed_out;
    }
    return false;
}

}

uint64_t InteractionRegistry::begin(
    const UserContext& user,
    UserInteractionOperation operation,
    std::string_view relying_party_id
) {
    std::lock_guard lock(mutex_);
    if(current_)
        throw std::runtime_error("Another interaction is already pending");
    if(
        nextRequestId_ == 0 ||
        nextRequestId_ == std::numeric_limits<uint64_t>::max()
    ) {
        throw std::overflow_error("Interaction request ID is exhausted");
    }

    const uint64_t request_id = nextRequestId_++;
    current_ = PendingInteraction{
        .requestId = request_id,
        .user = user.binding(),
        .operation = operation,
        .relyingPartyId = std::string(relying_party_id),
        .state = std::nullopt,
        .presenceResponse = std::nullopt,
        .passwordSubmitted = false,
        .cancelRequested = false,
        .responseClosed = false
    };
    passwordResponse_.reset();
    return request_id;
}

bool InteractionRegistry::transition(
    const UserContext& user,
    uint64_t request_id,
    UserInteractionState state
) {
    std::lock_guard lock(mutex_);
    if(
        request_id == 0 ||
        !current_ ||
        current_->requestId != request_id ||
        !same_user(current_->user, user)
    ) {
        throw std::runtime_error("Interaction request is no longer current");
    }
    if(!valid_transition(current_->state, state))
        throw std::logic_error("Invalid interaction state transition");
    if(
        current_->cancelRequested &&
        state != UserInteractionState::cancelled
    ) {
        return false;
    }

    current_->state = state;
    if(is_terminal(state)) {
        current_.reset();
        passwordResponse_.reset();
        condition_.notify_all();
    }
    return true;
}

void InteractionRegistry::respond_to_presence(
    const UserContext& user,
    uint64_t request_id,
    bool approved
) {
    std::lock_guard lock(mutex_);
    if(
        request_id == 0 ||
        !current_ ||
        current_->requestId != request_id ||
        !same_user(current_->user, user) ||
        current_->state != UserInteractionState::presence_required ||
        current_->responseClosed
    ) {
        throw std::runtime_error("Presence response is not currently accepted");
    }
    current_->presenceResponse = approved;
    current_->responseClosed = true;
    condition_.notify_all();
}

void InteractionRegistry::submit_password(
    const UserContext& user,
    uint64_t request_id,
    vauth::uv::SensitiveBytes password
) {
    std::lock_guard lock(mutex_);
    if(
        request_id == 0 ||
        !current_ ||
        current_->requestId != request_id ||
        !same_user(current_->user, user) ||
        current_->state != UserInteractionState::password_required ||
        current_->passwordSubmitted ||
        current_->cancelRequested
    ) {
        throw std::runtime_error("Password response is not currently accepted");
    }
    current_->passwordSubmitted = true;
    passwordResponse_.emplace(std::move(password));
    condition_.notify_all();
}

void InteractionRegistry::request_cancel(
    const UserContext& user,
    uint64_t request_id
) {
    std::lock_guard lock(mutex_);
    if(
        request_id == 0 ||
        !current_ ||
        current_->requestId != request_id ||
        !same_user(current_->user, user) ||
        !current_->state ||
        current_->responseClosed
    ) {
        throw std::runtime_error("Interaction cancellation is not accepted");
    }
    current_->cancelRequested = true;
    current_->responseClosed = true;
    condition_.notify_all();
}

PresenceWaitResult InteractionRegistry::wait_for_presence(
    const UserContext& user,
    uint64_t request_id,
    std::stop_token stop,
    std::chrono::steady_clock::duration timeout
) {
    if(timeout <= std::chrono::steady_clock::duration::zero())
        throw std::invalid_argument("Presence timeout must be positive");

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::unique_lock lock(mutex_);
    std::stop_callback wake_on_stop(stop, [this] {
        condition_.notify_all();
    });

    while(true) {
        if(
            !current_ ||
            current_->requestId != request_id ||
            !same_user(current_->user, user)
        ) {
            return PresenceWaitResult::invalidated;
        }
        if(stop.stop_requested()) {
            current_->responseClosed = true;
            return PresenceWaitResult::platform_cancelled;
        }
        if(current_->cancelRequested)
            return PresenceWaitResult::client_cancelled;
        if(current_->presenceResponse) {
            return *current_->presenceResponse
                ? PresenceWaitResult::approved
                : PresenceWaitResult::denied;
        }
        if(std::chrono::steady_clock::now() >= deadline) {
            current_->responseClosed = true;
            return PresenceWaitResult::timed_out;
        }
        condition_.wait_until(lock, deadline);
    }
}

PasswordWaitResult InteractionRegistry::wait_for_password(
    const UserContext& user,
    uint64_t request_id,
    std::stop_token stop,
    std::chrono::steady_clock::duration timeout
) {
    if(timeout <= std::chrono::steady_clock::duration::zero())
        throw std::invalid_argument("Password timeout must be positive");

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::unique_lock lock(mutex_);
    std::stop_callback wake_on_stop(stop, [this] {
        condition_.notify_all();
    });

    while(true) {
        if(
            !current_ ||
            current_->requestId != request_id ||
            !same_user(current_->user, user)
        ) {
            return {PasswordWaitStatus::invalidated, {}};
        }
        if(stop.stop_requested()) {
            current_->responseClosed = true;
            return {PasswordWaitStatus::platform_cancelled, {}};
        }
        if(current_->cancelRequested)
            return {PasswordWaitStatus::client_cancelled, {}};
        if(passwordResponse_) {
            vauth::uv::SensitiveBytes password = std::move(*passwordResponse_);
            passwordResponse_.reset();
            return {PasswordWaitStatus::provided, std::move(password)};
        }
        if(std::chrono::steady_clock::now() >= deadline) {
            current_->responseClosed = true;
            return {PasswordWaitStatus::timed_out, {}};
        }
        condition_.wait_until(lock, deadline);
    }
}

bool InteractionRegistry::cancellation_requested(
    const UserContext& user,
    uint64_t request_id
) const noexcept {
    try {
        std::lock_guard lock(mutex_);
        return
            request_id == 0 ||
            !current_ ||
            current_->requestId != request_id ||
            !same_user(current_->user, user) ||
            current_->cancelRequested;
    } catch(...) {
        return true;
    }
}

bool InteractionRegistry::end(
    const UserContext& user,
    uint64_t request_id
) noexcept {
    try {
        std::lock_guard lock(mutex_);
        if(
            request_id == 0 ||
            !current_ ||
            current_->requestId != request_id ||
            !same_user(current_->user, user)
        ) {
            return false;
        }
        current_.reset();
        passwordResponse_.reset();
        condition_.notify_all();
        return true;
    } catch(...) {
        return false;
    }
}

void InteractionRegistry::clear_for(
    const UserContext& user
) noexcept {
    try {
        std::lock_guard lock(mutex_);
        if(current_ && same_user(current_->user, user)) {
            current_.reset();
            passwordResponse_.reset();
            condition_.notify_all();
        }
    } catch(...) {
    }
}

std::optional<PendingInteraction> InteractionRegistry::current() const {
    std::lock_guard lock(mutex_);
    return current_;
}

}
