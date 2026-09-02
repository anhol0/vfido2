#pragma once

#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>
#include <tinycbor/cbor.h>
#include <array>
#include <stop_token>

#include "uhid_report.hpp"
#include "credentials/credential.hpp"
#include "error.hpp"

class CredentialKeyProvider;
class KeepaliveState;

enum class AssertionInteraction {
    None,
    Presence,
    Verification
};

[[nodiscard]] constexpr AssertionInteraction assertion_interaction(
    bool user_presence_requested,
    bool user_verification_requested
) noexcept {
    if(user_verification_requested) {
        return AssertionInteraction::Verification;
    }
    if(user_presence_requested) {
        return AssertionInteraction::Presence;
    }
    return AssertionInteraction::None;
}

[[nodiscard]] constexpr uint8_t assertion_authenticator_flags(
    bool user_present,
    bool user_verified
) noexcept {
    return static_cast<uint8_t>(
        (user_present ? 0x01 : 0x00) |
        (user_verified ? 0x04 : 0x00)
    );
}

[[nodiscard]] constexpr bool has_assertion_continuations(
    bool allow_list_empty,
    std::size_t credential_count
) noexcept {
    return allow_list_empty && credential_count > 1;
}

class AssertionSequence {
public:
    using Clock = std::chrono::steady_clock;

    void begin(
        uint32_t origin_cid,
        std::vector<StoredCredential> remaining_credentials,
        Clock::time_point now = Clock::now()
    );
    [[nodiscard]] std::optional<StoredCredential> next(
        uint32_t cid,
        Clock::time_point now = Clock::now()
    );
    void clear() noexcept;
    [[nodiscard]] uint32_t origin_cid() const noexcept;

private:
    // CTAP requires GetNextAssertion calls to arrive within 30 seconds.
    static constexpr auto TIMEOUT = std::chrono::seconds(30);

    std::vector<StoredCredential> credentials_;
    std::size_t index_ = 0;
    uint32_t originCid_ = 0;
    Clock::time_point lastUse_{};
};

class CTAPGetAssertionRequest {
public:
    uint32_t get_origin_cid() const {
        return sequence.origin_cid();
    };
    [[nodiscard]] bool has_rk_option() const noexcept {
        return rk_option_present;
    }
    bool parseRequest(std::vector<uint8_t> &payload);
    [[nodiscard]] std::optional<CTAPError> validation_error()
        const noexcept;
    std::vector<uint8_t> build_response(
        UHIDReport& r,
        std::stop_token stop,
        CredentialStore& store,
        CredentialKeyProvider& key_provider,
        KeepaliveState& keepalive
    );
    std::vector<uint8_t> build_response_next(
        uint32_t cid,
        std::stop_token stop,
        CredentialStore& store,
        CredentialKeyProvider& key_provider
    );
    void clear() {
        rpId.clear();
        clientDataHash.resize(0);
        allowList.clear();
        options = {
            {"uv", false},
            {"up", true}
        };
        rk_option_present = false;
        pin_auth_present = false;
        pin_protocol_present = false;
        userPresent = false;
        userVerified = false;
        sequence.clear();
    }
private:
    std::string rpId;
    std::vector<uint8_t> clientDataHash;
    std::vector<PublicKeyCredentialDescriptor> allowList;
    std::unordered_map<std::string, bool> options = {
        {"uv", false},
        {"up", true}
    };
    bool rk_option_present = false;
    bool pin_auth_present = false;
    bool pin_protocol_present = false;
    bool userPresent = false;
    bool userVerified = false;
    void parse_rp_id(CborValue &map);
    void parse_client_data_hash(CborValue &map);
    void parse_allow_list(CborValue &map);
    void parse_extensions(CborValue &map);
    void parse_options(CborValue &map);
    void parse_pin_auth(CborValue &map);
    void parse_pin_protocol(CborValue &map);
    using ParseFn = void (CTAPGetAssertionRequest::*) (CborValue &value);
    AssertionSequence sequence;
    std::vector<uint8_t> generate_single_credential_payload (
        StoredCredential &credential,
        std::optional<uint32_t> number_of_credentials,
        std::stop_token stop,
        CredentialStore& store,
        CredentialKeyProvider& key_provider
    );
    std::array<ParseFn, 8> dispatch_table = {
        nullptr,
        &CTAPGetAssertionRequest::parse_rp_id,
        &CTAPGetAssertionRequest::parse_client_data_hash,
        &CTAPGetAssertionRequest::parse_allow_list,
        &CTAPGetAssertionRequest::parse_extensions,
        &CTAPGetAssertionRequest::parse_options,
        &CTAPGetAssertionRequest::parse_pin_auth,
        &CTAPGetAssertionRequest::parse_pin_protocol
    };
};
