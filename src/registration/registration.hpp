#pragma once

#include "uhid_report.hpp"
#include "credentials/credential.hpp"
#include "error.hpp"

class CredentialKeyProvider;
class KeepaliveState;
#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <stop_token>
#include <string>
#include <sys/types.h>
#include <unordered_map>
#include <vector>

#include <tinycbor/cbor.h>

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
        displayName.clear();
    }
} UserEntity;

typedef struct PubKeyCredParam {
    std::string type;
    int alg = 0;
    void clear() {
        type.clear();
    }
} PubKeyCredParam;

class CTAPMakeCredentialRequest {
    public:
        RelyingParty rp;
        UserEntity user;
        std::vector<uint8_t> clientDataHash;
        std::vector<PubKeyCredParam> publicKeyCredParams;
        std::vector<PublicKeyCredentialDescriptor> excludeList;
        std::unordered_map<std::string, bool> options = {
            {"rk", false},
            {"uv", false}
        };
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
    private:
        void parse_client_data_hash(CborValue &map); // Required
        void parse_rp(CborValue &map);               // Required
        void parse_user(CborValue &map);             // Required
        void parse_pubkey_params(CborValue &map);    // Required
        void parse_exclude_list(CborValue &map);     // Optional
        void parse_extensions(CborValue &map);       // Optional
        void parse_options(CborValue &map);          // Optional
        void parse_pin_auth(CborValue &map);         // Optional
        void parse_pin_protocol(CborValue &map);     // Optional
        bool up_option_present = false;
        bool pin_auth_present = false;
        bool pin_protocol_present = false;
        using ParseFn = void (CTAPMakeCredentialRequest::*)(CborValue &value);
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
            clientDataHash.clear();
            publicKeyCredParams.clear();
            options = {
                {"rk", false},
                {"uv", false}
            };
            excludeList.clear();
            up_option_present = false;
            pin_auth_present = false;
            pin_protocol_present = false;
        }
};
