#pragma once

#include <string_view>

inline constexpr std::string_view VFIDO_AUTH_HANDLER_COMMAND =
    "vfido_auth_handler";

int run_vfido_auth_handler(int argc, char** argv) noexcept;
