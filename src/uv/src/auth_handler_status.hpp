#pragma once

#include <cstdint>

namespace vauth::uv {

inline constexpr int AUTH_HANDLER_STATUS_FD = 3;

enum class AuthHandlerStatus : uint8_t {
    fingerprint_required = 1,
    fingerprint_failed = 2,
    password_required = 3
};

}
