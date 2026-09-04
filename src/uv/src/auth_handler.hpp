#pragma once

#include <string_view>

inline constexpr std::string_view VAUTH_AUTH_HANDLER_COMMAND =
    "vauth_auth_handler";

int run_vauth_auth_handler(int argc, char** argv) noexcept;
