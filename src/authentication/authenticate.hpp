#pragma once

#include <optional>
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>
#include <tinycbor/cbor.h>
#include <array>
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
    bool parseRequest(std::vector<uint8_t> &payload);
    std::vector<uint8_t> build_response(UHIDReport &r);
    std::vector<uint8_t> build_response_next();
    void clear() {
        rpId.clear();
        clientDataHash.resize(0);
        allowList.clear();
        extensions.clear();
        options.clear();
        pinAuth.clear();
        pinProtocol = 0;
        cache.clear();
    }
private:
    std::string rpId;
    std::vector<uint8_t> clientDataHash;
    std::vector<PublicKeyCredentialDescriptor> allowList;
    std::unordered_map<std::string, ExtensionValue> extensions;
    std::unordered_map<std::string, bool> options = {
        {"rk", false},
        {"uv", false},
        {"up", true}
    };
    std::vector<uint8_t> pinAuth;
    uint64_t pinProtocol;
    bool parse_rp_id(CborValue &map);
    bool parse_client_data_hash(CborValue &map);
    bool parse_allow_list(CborValue &map);
    bool parse_extensions(CborValue &map);
    bool parse_options(CborValue &map);
    bool parse_pin_auth(CborValue &map);
    bool parse_pin_protocol(CborValue &map);
    using ParseFn = bool (CTAPGetAssertionRequest::*) (CborValue &value);
    StoredCredentialsCache cache;
    std::vector<uint8_t> generate_single_credential_payload (
        StoredCredential &credential,
        uint32_t number_of_credentials
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
