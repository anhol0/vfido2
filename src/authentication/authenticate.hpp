#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>
#include <tinycbor/cbor.h>
#include <array>
#include <variant>
#include "uhid_report.hpp"
#include "credentials/credential.hpp"

enum class Type {
        Bool,
        Int,
        String,
        Bytes,
        Map,
        Array,
        Unknown
};

typedef struct ExtensionValue{
    Type type;
    std::variant<bool, int64_t, std::string, std::vector<uint8_t>> value;
} ExtensionValue;

class CTAPGetAsserionRequest {
public:
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
    uint32_t pinProtocol;
    bool parseRequest(std::vector<uint8_t> &payload);
    std::vector<uint8_t> build_response(UHIDReport &r);
private:
    bool parse_rp_id(CborValue &map);
    bool parse_client_data_hash(CborValue &map);
    bool parse_allow_list(CborValue &map);
    bool parse_extensions(CborValue &map);
    bool parse_options(CborValue &map);
    bool parse_pin_auth(CborValue &map);
    bool parse_pin_protocol(CborValue &map);
    using ParseFn = bool (CTAPGetAsserionRequest::*) (CborValue &value);
    std::array<ParseFn, 8> dispatch_table = {
        nullptr,
        &CTAPGetAsserionRequest::parse_rp_id,
        &CTAPGetAsserionRequest::parse_client_data_hash,
        &CTAPGetAsserionRequest::parse_allow_list,
        &CTAPGetAsserionRequest::parse_extensions,
        &CTAPGetAsserionRequest::parse_options,
        &CTAPGetAsserionRequest::parse_pin_auth,
        &CTAPGetAsserionRequest::parse_pin_protocol
    }; 
    void clear() {

    }
};