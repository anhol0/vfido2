#ifndef REGISTRATION_HPP
#define REGISTRATION_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
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
    }
} UserEntity;

typedef struct PubKeyCredParam {
    std::string type;
    int alg;  
    void clear() {
        type.clear();
    }
} PubKeyCredParam;

class CTAPMakeCredentialRequest {
public:
    RelyingParty rp;
    UserEntity user;
    std::array<uint8_t, 32> clientDataHash;
    std::vector<PubKeyCredParam> publicKeyCredParams;
    std::vector<std::vector<uint8_t>> excludeList;
    std::unordered_map<std::string, std::string> extensions;

    bool rk = false;
    bool uv = false;
    bool up = true;
    bool parseRequest(std::vector<uint8_t> &payload);
private:
    bool parse_client_data_hash(CborValue &map);
    bool parse_rp(CborValue &map);
    bool parse_user(CborValue &map);
    bool parse_pubkey_params(CborValue &map);
    void clear() {
        rp.clear();
        user.clear();
        publicKeyCredParams.clear();
        excludeList.clear();
        extensions.clear();
    }
};

inline bool CTAPMakeCredentialRequest::parseRequest(
        std::vector<uint8_t> &payload
) {
    clear();
    uint8_t *buf = payload.data();
    size_t len = payload.size();
    CborParser parser;
    CborValue it;

    CborError err = cbor_parser_init(buf, len, 0, &parser, &it);
    if(err != CborNoError) {
        return false;
    }

    if(!cbor_value_is_map(&it)) {
        std::cerr << "Not a CBOR data!\n";
        return false;
    }

    CborValue map;
    cbor_value_enter_container(&it, &map);
    while(!cbor_value_at_end(&map)) {
        uint64_t key;
        cbor_value_get_uint64(&map, &key);
        cbor_value_advance_fixed(&map);
        switch(key) {
            case 1:  // clientDataHash (0x01) 
                if(!parse_client_data_hash(map)) {
                    return false;
                }
               break;
            case 2:  // RelyingParty (0x02)
                if(!parse_rp(map)) {
                    return false;
                }
                break;
            case 3:  // User (0x03)
               if(!parse_user(map)) {
                    return false;
               }
               break;
            case 4:  // PubKeyCredParameters (0x04)
                if(!parse_pubkey_params(map)) {
                    return false;
                }
                break;
        }
    }

    cbor_value_leave_container(&it, &map);

    return true; 
}

#endif
