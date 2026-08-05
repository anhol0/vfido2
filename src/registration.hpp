#pragma once

#include "response.hpp"
#include "uhid_report.hpp"
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <sys/types.h>
#include <unordered_map>
#include <variant>
#include <vector>

#include <tinycbor/cbor.h>

enum class Type {
        Bool,
        Int,
        String,
        Bytes,
        Map,
        Array,
        Unknown
};

typedef struct RelyingParty {
    std::string id;
    std::string name;
    void clear() {
        id.clear();
        name.clear();
    }
} RelyingParty;

typedef struct UserEntity {
    std::vector<uint8_t> id;
    std::string name;
    std::string displayName;
    void clear() {
        id.clear();
        name.clear();
    }
} UserEntity;

typedef struct PubKeyCredParam {
    std::string type;
    int alg;  
    void clear() {
        type.clear();
    }
} PubKeyCredParam;

typedef struct PublicKeyCredentialDescriptor {
    std::string type;
    std::vector<uint8_t> id;
    std::vector<std::string> transports;
} PublicKeyCredentialDescriptor;

typedef struct ExtensionValue{
    Type type;
    std::variant<bool, int64_t, std::string, std::vector<uint8_t>> value;
} ExtensionValue;

class CTAPMakeCredentialRequest {
    public:
        RelyingParty rp;
        UserEntity user;
        std::array<uint8_t, 32> clientDataHash;
        std::vector<PubKeyCredParam> publicKeyCredParams;
        std::vector<PublicKeyCredentialDescriptor> excludeList;
        std::unordered_map<std::string, ExtensionValue> extensions;
        std::unordered_map<std::string, bool> options = {
            {"rk", false},
            {"uv", false},
            {"up", true}
        };
        std::vector<uint8_t> pinAuth;
        uint64_t pinProtocol;
        bool parseRequest(std::vector<uint8_t> &payload);
        void build_response(UHIDReport &r);
    private:
        bool parse_client_data_hash(CborValue &map);
        bool parse_rp(CborValue &map);
        bool parse_user(CborValue &map);
        bool parse_pubkey_params(CborValue &map);
        bool parse_exclude_list(CborValue &map);
        bool parse_extensions(CborValue &map);
        bool parse_options(CborValue &map);
        bool parse_pin_auth(CborValue &map);
        bool parse_pin_protocol(CborValue &map);
        using ParseFn = bool (CTAPMakeCredentialRequest::*)(CborValue &value);
        std::array<ParseFn, 10> dispatch_table = {
            nullptr,
            &CTAPMakeCredentialRequest::parse_client_data_hash,
            &CTAPMakeCredentialRequest::parse_rp,
            &CTAPMakeCredentialRequest::parse_user,
            &CTAPMakeCredentialRequest::parse_pubkey_params,
            &CTAPMakeCredentialRequest::parse_exclude_list,
            &CTAPMakeCredentialRequest::parse_extensions,
            &CTAPMakeCredentialRequest::parse_options,
            &CTAPMakeCredentialRequest::parse_pin_auth,
            &CTAPMakeCredentialRequest::parse_pin_protocol
        };
        void clear() {
            rp.clear();
            user.clear();
            publicKeyCredParams.clear();
            excludeList.clear();
            extensions.clear();
        }
};

