#include "registration/registration.hpp"
#include <iostream>
#include <array>
#include <cstdint>
#include <cstring>
#include <sys/types.h>
#include <tinycbor/cbor.h>
#include <vector>

bool CTAPMakeCredentialRequest::parse_client_data_hash(CborValue &map) {
    size_t len = clientDataHash.size();

    CborError err = cbor_value_copy_byte_string(&map, clientDataHash.data(), &len, &map);

    if(err != CborNoError) {
        std::cerr << "Failed to parse clientDataHash\n";
        return false;
    }

    if(len != 32) {
        std::cerr << "Incorrect clientDataHash len\n";
        return false;
    }
    std::cout << "clientDataHash parsing successful!\n";
    return true;
}

bool CTAPMakeCredentialRequest::parse_rp(CborValue &map) {
    CborValue rpMap;
    cbor_value_enter_container(&map, &rpMap);

    while(!cbor_value_at_end(&rpMap)) {
        // Calculating and getting key length
        size_t keyLen;

        CborError err = cbor_value_calculate_string_length(&rpMap, &keyLen);
        if(err != CborNoError) {
            std::printf("Error calculating key length\n");
            return false;
        }
    
        std::vector<char> subkey(keyLen + 1);

        cbor_value_copy_text_string(&rpMap, subkey.data(), &keyLen, &rpMap);

        std::string strkey(subkey.data(), keyLen);

        // Calculating and getting value length
        size_t len;
        err = cbor_value_calculate_string_length(&rpMap, &len);
        if(err != CborNoError) {
            std::printf("Error calculating value length\n");
            return false;
        }
        std::vector<char> str(len + 1);
        cbor_value_copy_text_string(&rpMap, str.data(), &len, &rpMap);

        if(strkey == "id") {
            rp.id.assign(str.data(), len);
        } else if(strkey == "name") {
            rp.name.assign(str.data(), len);
        } else {
            std::cerr << "Incorrect ID in Relying Party map: " << strkey << ", skipping\n";
            cbor_value_advance(&rpMap);
        }
    }

    cbor_value_leave_container(&map, &rpMap);
    std::cout << "RP parsing successful!\n";
    return true;
}

// Parsing user
bool CTAPMakeCredentialRequest::parse_user(CborValue &map) {
    CborValue userMap;
    cbor_value_enter_container(&map, &userMap);

    while(!cbor_value_at_end(&userMap)) {
        // Key and Key Length
        size_t keyLen;

        CborError err = cbor_value_calculate_string_length(&userMap, &keyLen);
        if(err != CborNoError) {
             std::printf("Error calculating key length\n");
            return false;           
        }

        std::vector<char> subkey(keyLen + 1);

        cbor_value_copy_text_string(&userMap, subkey.data(), &keyLen, &userMap);
        std::string strkey(subkey.data(), keyLen);


        // Values and Value length due to variable size
        size_t len;
        // Calculating value length
        err = cbor_value_calculate_string_length(&userMap, &len);
        std::cout << "Data len: " << len << "\n";
        if(err != CborNoError) {
             std::printf("Error calculating value length\n");
            return false;           
        }

        if(strkey == "id") {
            std::vector<uint8_t> id(len);
            cbor_value_copy_byte_string(&userMap, id.data(), &len, &userMap);
            user.id.insert(user.id.end(), id.begin(), id.begin()+len);
        } else if(strkey == "name") {
            std::vector<char> name(len + 1);
            cbor_value_copy_text_string(&userMap, name.data(), &len, &userMap);
            std::cout << "Name = " << name.data() << std::endl;
            user.name.assign(name.data(), len);
        } else if(strkey == "displayName") {
            std::vector<char> displayName(len + 1);
            cbor_value_copy_text_string(&userMap, displayName.data(), &len, &userMap);
            std::cout << "Display Name = " << std::string(displayName.data(), len) << std::endl;
            user.displayName.assign(displayName.data(), len);
        } else {
            std::cerr << "Incorrect ID in User map: " << strkey << ", skipping\n";
            cbor_value_advance(&userMap);
        }
    }
    cbor_value_leave_container(&map, &userMap);
    std::cout << "User parsing successful!\n";
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
            size_t keyLen;

            CborError err = cbor_value_calculate_string_length(&item, &keyLen);
            if(err != CborNoError) {
                 std::printf("Error calculating key length\n");
                return false;           
            }
            
            std::vector<char> subkey(keyLen + 1);

            cbor_value_copy_text_string(&item, subkey.data(), &keyLen, &item);

            std::string strkey(subkey.data(), keyLen);

            if(strkey == "type") {
                size_t len;

                CborError err = cbor_value_calculate_string_length(&item, &len);

                if(err != CborNoError) {
                     std::printf("Error calculating key length\n");
                    return false;           
                }
                
                std::vector<char> type(len + 1);

                cbor_value_copy_text_string(&item, type.data(), &len, &item);
                p.type.assign(type.data(), len);
            } else if(strkey =="alg") {
                cbor_value_get_int(&item, &p.alg);
                cbor_value_advance_fixed(&item);
            } else {
                std::cerr << "Incorrect ID in Public Key Parameters map: " << strkey << ", skipping\n";
                cbor_value_advance(&item);
            }

        }
        publicKeyCredParams.push_back(p);
        cbor_value_leave_container(&arr, &item);
    }
    cbor_value_leave_container(&map, &arr);
    std::cout << "PubKeyParam parsing successful!\n";
    return true;
}

bool CTAPMakeCredentialRequest::parse_exclude_list(CborValue &map) {
    CborValue arr;
    cbor_value_enter_container(&map, &arr);
    
    while(!cbor_value_at_end(&arr)) {
        CborValue item;
        cbor_value_enter_container(&arr, &item);

        PublicKeyCredentialDescriptor d;
        while(!cbor_value_at_end(&item)) {
            size_t keyLen;

            CborError err = cbor_value_calculate_string_length(&item, &keyLen);
            if(err != CborNoError) {
                 std::printf("Error calculating key length\n");
                return false;           
            }
            
            std::vector<char> subkey(keyLen + 1);

            cbor_value_copy_text_string(&item, subkey.data(), &keyLen, &item);

            std::string strkey(subkey.data(), keyLen);

            if(strkey == "type") {
                size_t len;

                CborError err = cbor_value_calculate_string_length(&item, &len);

                if(err != CborNoError) {
                     std::printf("Error calculating key length\n");
                    return false;           
                }
                
                std::vector<char> type(len + 1);

                cbor_value_copy_text_string(&item, type.data(), &len, &item);
                d.type.assign(type.data(), len);
            } else if(strkey =="id") {
                size_t len;
                CborError err = cbor_value_calculate_string_length(&item, &len);
                if(err != CborNoError) {
                     std::printf("Error calculating key length\n");
                    return false;           
                }
                std::vector<uint8_t> id_buf(len);
                cbor_value_copy_byte_string(&item, id_buf.data(), &len, &item);
                d.id.insert(d.id.end(), id_buf.begin(), id_buf.begin()+len);
            } else if(strkey == "transports") {
                CborValue transport;
                cbor_value_enter_container(&item, &transport);
                while(!cbor_value_at_end(&transport)) {
                    size_t tlen;

                    CborError err = cbor_value_calculate_string_length(&transport, &tlen);

                    if(err != CborNoError) {
                        std::cerr << "Error parsing exclude list transport options";
                        return false;
                    }
                    
                    std::vector<char> string(tlen + 1);
                    cbor_value_copy_text_string(&transport, string.data(), &tlen, &transport);
                    d.transports.push_back(std::string(string.data(), tlen)); 
                }
                cbor_value_leave_container(&item, &transport);
            } else {
                std::cerr << "Incorrect key in Exclude List map: " << strkey << ", skipping\n";
                cbor_value_advance(&item);
            }

        }
        excludeList.push_back(d);
        cbor_value_leave_container(&arr, &item);
    }
    cbor_value_leave_container(&map, &arr);
    std::cout << "Exclude list parsing successful!\n";
    return true;
}

bool CTAPMakeCredentialRequest::parse_extensions(CborValue &map) {
    CborValue extMap;
    cbor_value_enter_container(&map, &extMap);

    while(!cbor_value_at_end(&extMap)) {

        size_t keyLen;
        cbor_value_calculate_string_length(&extMap, &keyLen);

        std::vector<char> key(keyLen + 1);

        cbor_value_copy_text_string(&extMap, key.data(), &keyLen, &extMap);

        std::string extName(key.data(), keyLen);

        ExtensionValue ext;

        if(cbor_value_is_boolean(&extMap)) {

            bool v;
            cbor_value_get_boolean(&extMap, &v);

            ext.type = Type::Bool;
            ext.value = v;

            cbor_value_advance_fixed(&extMap);

        } else if(cbor_value_is_integer(&extMap)) {

            int64_t v;
            cbor_value_get_int64(&extMap, &v);

            ext.type = Type::Int;
            ext.value = v;

            cbor_value_advance_fixed(&extMap);

        } else if(cbor_value_is_text_string(&extMap)) {

            size_t len;
            cbor_value_calculate_string_length(&extMap, &len);

            std::vector<char> str(len + 1);

            cbor_value_copy_text_string(
                &extMap,
                str.data(),
                &len,
                &extMap
            );

            ext.type = Type::String;
            ext.value = std::string(str.data(), len);

        } else if(cbor_value_is_byte_string(&extMap)) {

            size_t len;
            cbor_value_calculate_string_length(&extMap, &len);

            std::vector<uint8_t> bytes(len);

            cbor_value_copy_byte_string(&extMap, bytes.data(), &len, &extMap);

            ext.type = Type::Bytes;
            ext.value = bytes;
        }
        else {
            std::cerr << "Unsupported extension type\n";
            return false;
        }

        extensions[extName] = ext;
    }

    cbor_value_leave_container(&map, &extMap);
    std::cout << "Extensions parsing successful!\n";
    return true;
}

bool CTAPMakeCredentialRequest::parse_options(CborValue &map) {
    CborValue optMap;
    cbor_value_enter_container(&map, &optMap);
    while(!cbor_value_at_end(&optMap)) {
        size_t keyLen;
        CborError err = cbor_value_calculate_string_length(&optMap, &keyLen);
        if(err != CborNoError) {
            std::cerr << "Error calculating key length\n";
            return false;
        }
        std::vector<char> keyBuf(keyLen + 1);
        cbor_value_copy_text_string(&optMap, keyBuf.data(), &keyLen, &optMap);
        std::string strkey(keyBuf.data(), keyLen);
        if(strkey == "rk" || strkey == "up" || strkey == "uv") {
            bool value;
            cbor_value_get_boolean(&optMap, &value);
            cbor_value_advance_fixed(&optMap);
            options[strkey] = value;
        } else {
            std::cerr << "Unknown option for Option map!\n";
            cbor_value_advance(&optMap);
        }
    }
    cbor_value_leave_container(&map, &optMap);
    return true;
}

bool CTAPMakeCredentialRequest::parse_pin_auth(CborValue &map) {
    size_t size;
    cbor_value_calculate_string_length(&map, &size);
    std::vector<uint8_t> cdhTrunc(size);
    cbor_value_copy_byte_string(&map, cdhTrunc.data(), &size, &map);
    std::cout << "PinAuth parsing successful!\n";
    return true;
}

bool CTAPMakeCredentialRequest::parse_pin_protocol(CborValue &map) {
    cbor_value_get_uint64(&map, &pinProtocol);
    cbor_value_advance_fixed(&map);
    return true;
}
