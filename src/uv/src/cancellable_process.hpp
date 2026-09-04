#pragma once

#include <chrono>
#include <stop_token>
#include <string>
#include <vector>

namespace vauth::uv {

// Runs a program in its own process group. Cancellation or timeout terminates
// and reaps the whole group before the corresponding exception is thrown.
int run_cancellable_program(
    const std::string& path,
    const std::vector<std::string>& arguments,
    std::stop_token stop,
    std::chrono::steady_clock::duration timeout
);

}
