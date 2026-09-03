#pragma once

#include <cstdint>
#include <stop_token>
#include <string>

class KeepaliveState;

struct LocalUserIdentity {
    uint32_t uid;
    std::string name;
};

int authenticate_user(
    const std::string &username,
    const std::string &process_name,
    const std::string &confdir,
    std::stop_token stop,
    KeepaliveState& keepalive
);

LocalUserIdentity get_local_user_identity();
bool collect_consent(
    const std::string& question,
    std::stop_token stop,
    KeepaliveState& keepalive
);
