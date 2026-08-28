#pragma once

#include <stop_token>
#include <string>

int authenticate_user(
    const std::string &username,
    const std::string &process_name,
    const std::string &confdir,
    std::stop_token stop
);

std::string get_user_name();
bool collect_consent(const std::string& question, std::stop_token stop);
