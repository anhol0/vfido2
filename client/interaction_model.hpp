#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace vauth::client {

enum class InteractionState {
    presence_required,
    presence_approved,
    presence_denied,
    verification_started,
    fingerprint_required,
    fingerprint_failed,
    password_required,
    verification_succeeded,
    verification_failed,
    cancelled,
    timed_out
};

struct InteractionEvent {
    uint64_t generation;
    uint64_t requestId;
    InteractionState state;
    std::string operation;
    std::string relyingPartyId;
};

[[nodiscard]] std::optional<InteractionState> parse_interaction_state(
    std::string_view state
) noexcept;

[[nodiscard]] bool is_terminal(InteractionState state) noexcept;

class InteractionTracker {
public:
    explicit InteractionTracker(uint64_t generation) noexcept;

    [[nodiscard]] bool accept(const InteractionEvent& event) noexcept;
    [[nodiscard]] bool is_active(uint64_t request_id) const noexcept;

private:
    uint64_t generation_;
    std::optional<uint64_t> activeRequestId_;
};

enum class ViewKind {
    presence,
    fingerprint,
    password,
    status
};

enum class AnimationKind {
    none,
    waiting,
    success,
    failure
};

struct UiPresentation {
    ViewKind view = ViewKind::status;
    AnimationKind animation = AnimationKind::none;
    std::string title;
    std::string message;
    std::string relyingPartyId;
    bool terminal = false;
};

class UiModel {
public:
    [[nodiscard]] UiPresentation apply(const InteractionEvent& event);

private:
    ViewKind currentView_ = ViewKind::status;
};

} // namespace vauth::client
