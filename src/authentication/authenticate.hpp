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
#include "extensions.hpp"

class CTAPGetAssertionRequest {
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
    uint64_t pinProtocol;
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
    using ParseFn = bool (CTAPGetAssertionRequest::*) (CborValue &value);
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
    void clear() {
        rpId.clear();
        clientDataHash.resize(0);
        allowList.clear();
        extensions.clear();
        options.clear();
        pinAuth.clear();
        pinProtocol = 0;
    }
};