#pragma once

#include <string>

int authenticate_user(
    const std::string &username,
    const std::string &process_name,
    const std::string &confdir
);

std::string get_user_name();
bool collect_consent(std::string question);
