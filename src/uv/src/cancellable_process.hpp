#pragma once

#include <stop_token>
#include <string>
#include <vector>

namespace vfido::uv {

// Runs a program in its own process group. Cancellation terminates and reaps
// the whole group before OperationCancelled is thrown.
int run_cancellable_program(
    const std::string& path,
    const std::vector<std::string>& arguments,
    std::stop_token stop
);

}
