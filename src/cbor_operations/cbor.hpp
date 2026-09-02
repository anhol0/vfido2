#pragma once

#include "credentials/credential.hpp"
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <vector>

enum class CborEncodingFailure {
    resource_limit,
    invalid_structure
};

class CborEncodingError : public std::runtime_error {
public:
    explicit CborEncodingError(CborEncodingFailure failure);

    [[nodiscard]] CborEncodingFailure failure() const noexcept;

private:
    CborEncodingFailure failure_;
};

std::vector<uint8_t> build_getinfo_response();
std::vector<uint8_t> build_cose_key(
    std::span<const uint8_t> x,
    std::span<const uint8_t> y
);
std::vector<uint8_t> build_authenticatorMakeCredential_response(
    std::span<const uint8_t> auth_data,
    std::span<const uint8_t> signData
);
std::vector<uint8_t> build_authenticatorGetAssertion_response(
    std::span<const uint8_t> auth_data,
    std::span<const uint8_t> signature,
    bool uv,
    const StoredCredential* credential = nullptr,
    std::optional<uint32_t> number_of_credentials = std::nullopt
);
