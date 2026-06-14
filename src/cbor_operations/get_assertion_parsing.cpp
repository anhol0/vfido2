#include "authentication/authenticate.hpp"
#include <iostream>

// 0x01 — rpId (text string)
bool CTAPGetAssertionRequest::parse_rp_id(CborValue &map) {
    size_t len;
    CborError err = cbor_value_calculate_string_length(&map, &len);
    if (err != CborNoError) {
        std::cerr << "Failed to calculate rpId length\n";
        return false;
    }

    std::vector<char> buf(len + 1);
    cbor_value_copy_text_string(&map, buf.data(), &len, &map);
    rpId.assign(buf.data(), len);

    std::cout << "rpId parsing successful!\n";
    return true;
}

// 0x02 — clientDataHash (32-byte byte string)
bool CTAPGetAssertionRequest::parse_client_data_hash(CborValue &map) {
    size_t len;
    CborError err = cbor_value_calculate_string_length(&map, &len);
    if (err != CborNoError) {
        std::cerr << "Failed to calculate clientDataHash length\n";
        return false;
    }
    clientDataHash.resize(len);
    err = cbor_value_copy_byte_string(
        &map, clientDataHash.data(), &len, &map
    );
    if (err != CborNoError) {
        std::cerr << "Failed to parse clientDataHash\n";
        return false;
    }
    if (len != 32) {
        std::cerr << "Incorrect clientDataHash length: " << len << "\n";
        return false;
    }

    std::cout << "clientDataHash parsing successful!\n";
    return true;
}

// 0x03 — allowList (array of PublicKeyCredentialDescriptor)
// Mirrors parse_exclude_list from MakeCredential exactly.
bool CTAPGetAssertionRequest::parse_allow_list(CborValue &map) {
    CborValue arr;
    cbor_value_enter_container(&map, &arr);

    while (!cbor_value_at_end(&arr)) {
        CborValue item;
        cbor_value_enter_container(&arr, &item);

        PublicKeyCredentialDescriptor d;

        while (!cbor_value_at_end(&item)) {
            size_t keyLen;
            CborError err = cbor_value_calculate_string_length(&item, &keyLen);
            if (err != CborNoError) {
                std::cerr << "Error calculating key length in allowList\n";
                return false;
            }

            std::vector<char> subkey(keyLen + 1);
            cbor_value_copy_text_string(&item, subkey.data(), &keyLen, &item);
            std::string strkey(subkey.data(), keyLen);

            if (strkey == "type") {
                size_t len;
                err = cbor_value_calculate_string_length(&item, &len);
                if (err != CborNoError) {
                    std::cerr << "Error calculating type length in allowList\n";
                    return false;
                }
                std::vector<char> type(len + 1);
                cbor_value_copy_text_string(&item, type.data(), &len, &item);
                d.type.assign(type.data(), len);

            } else if (strkey == "id") {
                size_t len;
                err = cbor_value_calculate_string_length(&item, &len);
                if (err != CborNoError) {
                    std::cerr << "Error calculating id length in allowList\n";
                    return false;
                }
                std::vector<uint8_t> id_buf(len);
                cbor_value_copy_byte_string(&item, id_buf.data(), &len, &item);
                d.id.insert(d.id.end(), id_buf.begin(), id_buf.begin() + len);

            } else if (strkey == "transports") {
                CborValue transport;
                cbor_value_enter_container(&item, &transport);
                while (!cbor_value_at_end(&transport)) {
                    size_t tlen;
                    err = cbor_value_calculate_string_length(&transport, &tlen);
                    if (err != CborNoError) {
                        std::cerr << "Error parsing allowList transport\n";
                        return false;
                    }
                    std::vector<char> str(tlen + 1);
                    cbor_value_copy_text_string(&transport, str.data(), &tlen, &transport);
                    d.transports.push_back(std::string(str.data(), tlen));
                }
                cbor_value_leave_container(&item, &transport);

            } else {
                std::cerr << "Unknown key in allowList descriptor: " << strkey << ", skipping\n";
                cbor_value_advance(&item);
            }
        }

        allowList.push_back(d);
        cbor_value_leave_container(&arr, &item);
    }

    cbor_value_leave_container(&map, &arr);
    std::cout << "allowList parsing successful!\n";
    return true;
}

// 0x04 — extensions: reuse your existing parse_extensions logic verbatim,
//         just called on the GetAssertion instance.
bool CTAPGetAssertionRequest::parse_extensions(CborValue &map) {
    // identical body to CTAPMakeCredentialRequest::parse_extensions
    CborValue extMap;
    cbor_value_enter_container(&map, &extMap);

    while (!cbor_value_at_end(&extMap)) {
        size_t keyLen;
        cbor_value_calculate_string_length(&extMap, &keyLen);
        std::vector<char> key(keyLen + 1);
        cbor_value_copy_text_string(&extMap, key.data(), &keyLen, &extMap);
        std::string extName(key.data(), keyLen);

        ExtensionValue ext;

        if (cbor_value_is_boolean(&extMap)) {
            bool v;
            cbor_value_get_boolean(&extMap, &v);
            ext.type = Type::Bool;
            ext.value = v;
            cbor_value_advance_fixed(&extMap);

        } else if (cbor_value_is_integer(&extMap)) {
            int64_t v;
            cbor_value_get_int64(&extMap, &v);
            ext.type = Type::Int;
            ext.value = v;
            cbor_value_advance_fixed(&extMap);

        } else if (cbor_value_is_text_string(&extMap)) {
            size_t len;
            cbor_value_calculate_string_length(&extMap, &len);
            std::vector<char> str(len + 1);
            cbor_value_copy_text_string(&extMap, str.data(), &len, &extMap);
            ext.type = Type::String;
            ext.value = std::string(str.data(), len);

        } else if (cbor_value_is_byte_string(&extMap)) {
            size_t len;
            cbor_value_calculate_string_length(&extMap, &len);
            std::vector<uint8_t> bytes(len);
            cbor_value_copy_byte_string(&extMap, bytes.data(), &len, &extMap);
            ext.type = Type::Bytes;
            ext.value = bytes;

        } else {
            std::cerr << "Unsupported extension type\n";
            return false;
        }

        extensions[extName] = ext;
    }

    cbor_value_leave_container(&map, &extMap);
    std::cout << "Extensions parsing successful!\n";
    return true;
}

// 0x05 — options (map of string -> bool; GetAssertion only uses "up" and "uv")
bool CTAPGetAssertionRequest::parse_options(CborValue &map) {
    CborValue optMap;
    cbor_value_enter_container(&map, &optMap);

    while (!cbor_value_at_end(&optMap)) {
        size_t keyLen;
        CborError err = cbor_value_calculate_string_length(&optMap, &keyLen);
        if (err != CborNoError) {
            std::cerr << "Error calculating option key length\n";
            return false;
        }
        std::vector<char> keyBuf(keyLen + 1);
        cbor_value_copy_text_string(&optMap, keyBuf.data(), &keyLen, &optMap);
        std::string strkey(keyBuf.data(), keyLen);

        // GetAssertion options: "up" and "uv" only ("rk" is MakeCredential-only)
        if (strkey == "up" || strkey == "uv") {
            bool value;
            cbor_value_get_boolean(&optMap, &value);
            cbor_value_advance_fixed(&optMap);
            options[strkey] = value;
        } else {
            std::cerr << "Unknown option key in GetAssertion options: " << strkey << "\n";
            cbor_value_advance(&optMap);
        }
    }

    cbor_value_leave_container(&map, &optMap);
    std::cout << "Options parsing successful!\n";
    return true;
}

// 0x06 — pinAuth (byte string, first 16 bytes of HMAC-SHA-256)
bool CTAPGetAssertionRequest::parse_pin_auth(CborValue &map) {
    size_t len;
    CborError err = cbor_value_calculate_string_length(&map, &len);
    if (err != CborNoError) {
        std::cerr << "Error calculating pinAuth length\n";
        return false;
    }
    pinAuth.resize(len);
    cbor_value_copy_byte_string(&map, pinAuth.data(), &len, &map);
    std::cout << "pinAuth parsing successful!\n";
    return true;
}

// 0x07 — pinProtocol (unsigned int)
bool CTAPGetAssertionRequest::parse_pin_protocol(CborValue &map) {
    cbor_value_get_uint64(&map, &pinProtocol);
    cbor_value_advance_fixed(&map);
    std::cout << "pinProtocol parsing successful!\n";
    return true;
}