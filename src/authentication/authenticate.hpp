#pragma once

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
#include "extensions.hpp"

// Cache class
class StoredCredentialsCache {
    private:
    std::vector<StoredCredential> cache = {};
    uint32_t index = 0;
    uint32_t size = 0;
    public:
    operator std::vector<StoredCredential>() const { return cache; }
    StoredCredentialsCache& operator =(const std::vector<StoredCredential>& other) {
        cache = other;
        size = cache.size();
        index = 0;
        return *this;
    }
    std::optional<StoredCredential> get_next() {
        if(index >= cache.size()) { return std::nullopt; }
        size = cache.size() - index;
        return cache[index++];
    }
    int32_t get_size() {
        return size;
    }
    void clear() {
        cache.clear();
        index = 0;
        size = 0;
    }
};

class CTAPGetAssertionRequest {
public:
    uint32_t get_origin_cid() const {
        return origin_cid;
    };
    void set_origin_cid(uint32_t cid) {
        origin_cid = cid;
    }
    [[nodiscard]] bool has_rk_option() const noexcept {
        return rk_option_present;
    }
    bool parseRequest(std::vector<uint8_t> &payload);
    std::vector<uint8_t> build_response(
        UHIDReport& r,
        std::stop_token stop,
        CredentialStore& store
    );
    std::vector<uint8_t> build_response_next(
        std::stop_token stop,
        CredentialStore& store
    );
    void clear() {
        rpId.clear();
        clientDataHash.resize(0);
        allowList.clear();
        extensions.clear();
        options = {
            {"uv", false},
            {"up", true}
        };
        rk_option_present = false;
        pinAuth.clear();
        pinProtocol = 0;
        origin_cid = 0;
        cache.clear();
    }
private:
    uint32_t origin_cid = 0;
    std::string rpId;
    std::vector<uint8_t> clientDataHash;
    std::vector<PublicKeyCredentialDescriptor> allowList;
    std::unordered_map<std::string, ExtensionValue> extensions;
    std::unordered_map<std::string, bool> options = {
        {"uv", false},
        {"up", true}
    };
    bool rk_option_present = false;
    std::vector<uint8_t> pinAuth;
    uint64_t pinProtocol = 0;
    void parse_rp_id(CborValue &map);
    void parse_client_data_hash(CborValue &map);
    void parse_allow_list(CborValue &map);
    void parse_extensions(CborValue &map);
    void parse_options(CborValue &map);
    void parse_pin_auth(CborValue &map);
    void parse_pin_protocol(CborValue &map);
    using ParseFn = void (CTAPGetAssertionRequest::*) (CborValue &value);
    StoredCredentialsCache cache;
    std::vector<uint8_t> generate_single_credential_payload (
        StoredCredential &credential,
        std::optional<uint32_t> number_of_credentials,
        std::stop_token stop,
        CredentialStore& store
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
    void clear_cache() {
        cache.clear();
    }
};
