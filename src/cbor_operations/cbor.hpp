#pragma once

#include "credentials/credential.hpp"
#include <optional>
#include <vector>
#include <cstdint>

std::vector<uint8_t> build_getinfo_response();
std::vector<uint8_t> build_cose_key(std::vector<uint8_t> &x, std::vector<uint8_t> &y);
std::vector<uint8_t> build_authenticatorMakeCredential_response(std::vector<uint8_t> &authData);
std::vector<uint8_t> build_authenticatorGetAssertion_response(
        std::vector<uint8_t> &authData,
        std::vector<uint8_t> &signature,
        std::optional<StoredCredential> credential = std::nullopt,
        uint32_t numberOfCredentials = 1
);
