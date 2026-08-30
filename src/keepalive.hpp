#pragma once

#include <atomic>
#include <cstdint>

enum class KeepaliveStatus : std::uint8_t {
    processing = 0x01,
    up_needed = 0x02
};

static_assert(static_cast<std::uint8_t>(KeepaliveStatus::processing) == 0x01);
static_assert(static_cast<std::uint8_t>(KeepaliveStatus::up_needed) == 0x02);

class KeepaliveState {
public:
    [[nodiscard]] KeepaliveStatus get() const noexcept {
        return status_.load(std::memory_order_relaxed);
    }

    void set(KeepaliveStatus status) noexcept {
        status_.store(status, std::memory_order_relaxed);
    }

private:
    std::atomic<KeepaliveStatus> status_{KeepaliveStatus::processing};
};

class UserActionKeepaliveGuard {
public:
    explicit UserActionKeepaliveGuard(KeepaliveState& state) noexcept
        : state_(state) {
        state_.set(KeepaliveStatus::up_needed);
    }

    ~UserActionKeepaliveGuard() {
        state_.set(KeepaliveStatus::processing);
    }

    UserActionKeepaliveGuard(const UserActionKeepaliveGuard&) = delete;
    UserActionKeepaliveGuard& operator=(const UserActionKeepaliveGuard&) = delete;

private:
    KeepaliveState& state_;
};
