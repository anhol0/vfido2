#include "registration.hpp"
#include <cstring>
#include <tinycbor/cbor.h>

bool CTAPMakeCredentialRequest::parse_client_data_hash(CborValue &map) {
    size_t len = clientDataHash.size();

    CborError err = cbor_value_copy_byte_string(&map, clientDataHash.data(), &len, nullptr);

    if(err != CborNoError) {
        std::cerr << "Failed to parse clientDataHash\n";
        return false;
    }

    if(len != 32) {
        std::cerr << "Incorrect clientDataHash len\n";
        return false;
    }

    return true;
}

bool CTAPMakeCredentialRequest::parse_rp(CborValue &map) {
    CborValue rpMap;
    cbor_value_enter_container(&map, &rpMap);

    while(!cbor_value_at_end(&rpMap)) {
        const char *subkey;
        size_t keyLen;

        cbor_value_get_text_string_chunk(&rpMap, &subkey, &keyLen, nullptr);
        cbor_value_advance(&rpMap);

        std::string strkey(subkey, keyLen);

        if(strkey == "id") {
            const char *str;
            size_t len;
            cbor_value_get_text_string_chunk(&rpMap, &str, &len, nullptr);
            rp.id.assign(str, len);
        } else if(strkey == "name") {
            const char *str;
            size_t len;
            cbor_value_get_text_string_chunk(&rpMap, &str, &len, nullptr);
            rp.name.assign(str, len);
        } else {
            std::cerr << "Incorrect ID in Relying Party map\n";
            return false;
        }
        cbor_value_advance(&rpMap);
    }

    cbor_value_leave_container(&map, &rpMap);
    return true;
}

bool CTAPMakeCredentialRequest::parse_user(CborValue &map) {
    CborValue userMap;
    cbor_value_enter_container(&map, &userMap);

    while(!cbor_value_at_end(&userMap)) {
        const uint8_t *id;
        const char *name;
        size_t len;
        const char *subkey;
        size_t keyLen;

        cbor_value_get_text_string_chunk(&userMap, &subkey, &keyLen, nullptr);
        cbor_value_advance(&userMap);

        std::string strkey(subkey, keyLen);
        if(strkey == "id") {
            cbor_value_get_byte_string_chunk(&userMap, &id, &len, nullptr);
            user.id.insert(user.id.end(), id, id+len);
        } else if(strkey == "name") {
            cbor_value_get_text_string_chunk(&userMap, &name, &len, nullptr);
            user.name.assign(name, len);
        } else if(strkey == "displayName") {
            cbor_value_get_text_string_chunk(&userMap, &name, &len, nullptr);
            user.displayName.assign(name, len);
        }
        cbor_value_advance(&userMap);
    }
    cbor_value_leave_container(&map, &userMap);
    return true;
}

bool CTAPMakeCredentialRequest::parse_pubkey_params(CborValue &map) {
    CborValue arr;
    cbor_value_enter_container(&map, &arr);
    
    while(!cbor_value_at_end(&arr)) {
        CborValue item;
        cbor_value_enter_container(&arr, &item);

        PubKeyCredParam p;
        while(!cbor_value_at_end(&item)) {
            const char *subkey;
            size_t keyLen;
            cbor_value_get_text_string_chunk(&item, &subkey, &keyLen, nullptr);
            cbor_value_advance(&item);

            std::string strkey(subkey, keyLen);

            if(strkey == "type") {
                const char *type;
                size_t len;
                cbor_value_get_text_string_chunk(&item, &type, &len, nullptr);
                p.type.assign(type, len);
            } else if(strkey =="alg") {
                cbor_value_get_int(&item, &p.alg);
            }

            cbor_value_advance(&item);
        }
        publicKeyCredParams.push_back(p);
        cbor_value_leave_container(&arr, &item);
        cbor_value_advance(&arr);
    }
    cbor_value_leave_container(&map, &arr);
    return true;
}
