#include "cbor.hpp"
#include "const.hpp"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <iostream>
#include <nlohmann/detail/value_t.hpp>
#include <stdexcept>
#include <string>
#include <tinycbor/cbor.h>
#include <vector>

std::vector<uint8_t> build_getinfo_response() {
    uint8_t buffer[256];

    CborEncoder encoder;
    CborEncoder map;
    CborEncoder versions;
    CborEncoder options;

    cbor_encoder_init(&encoder, buffer, sizeof(buffer), 0);

    // map with 3 entries
    cbor_encoder_create_map(&encoder, &map, 3);

    // 1: ["FIDO_2_0"]
    cbor_encode_uint(&map, 1);

    cbor_encoder_create_array(&map, &versions, 1);
    cbor_encode_text_stringz(&versions, "FIDO_2_0");
    cbor_encoder_close_container(&map, &versions);

    // 3: aaguid (16 zero bytes)
    cbor_encode_uint(&map, 3);

    cbor_encode_byte_string(&map, aaguid.data(), 16);

    // 4: options
    cbor_encode_uint(&map, 4);

    cbor_encoder_create_map(&map, &options, 3);

    cbor_encode_text_stringz(&options, "rk");
    cbor_encode_boolean(&options, false);

    cbor_encode_text_stringz(&options, "up");
    cbor_encode_boolean(&options, true);

    cbor_encode_text_stringz(&options, "uv");
    cbor_encode_boolean(&options, false);

    // cbor_encode_text_stringz(&options, "clientPin");
    // cbor_encode_boolean(&options, true);

    cbor_encoder_close_container(&map, &options);

    cbor_encoder_close_container(&encoder, &map);

    size_t len = cbor_encoder_get_buffer_size(&encoder, buffer);

    std::vector<uint8_t> out;

    // CTAP success byte
    out.push_back(0x00);

    out.insert(out.end(), buffer, buffer + len);

    return out;
}

std::vector<uint8_t> pad32(std::vector<uint8_t> &v) {
    if(v.size() > 32)
        throw std::runtime_error("ECC coordinate too large!");
    
    std::vector<uint8_t> out(32, 0);
    memcpy(out.data() + (32 - v.size()), v.data(), v.size());
    return out;
}

std::vector<uint8_t> build_cose_key(
        std::vector<uint8_t> &x, 
        std::vector<uint8_t> &y
) {
    auto x_pad = pad32(x);
    auto y_pad = pad32(y);
    uint8_t buf[256];
    CborEncoder encoder;
    CborEncoder map;
    cbor_encoder_init(&encoder, buf, sizeof(buf), 0);

    CborError e = cbor_encoder_create_map(&encoder, &map, 5);
    if(e != CborNoError)
        throw std::runtime_error("Cannot create CBOR map: " + std::string(cbor_error_string(e)));
    cbor_encode_int(&map, 1);
    cbor_encode_int(&map, 2);

    cbor_encode_int(&map, 3);
    cbor_encode_int(&map, -7);

    cbor_encode_int(&map, -1);
    cbor_encode_int(&map, 1);

    cbor_encode_int(&map, -2);
    std::cout << "X-coordinate for public key: ";
    for (auto byte : x_pad) {
        std::cout << std::format("{:02x}", byte);
    }
    std::cout << std::endl;
    cbor_encode_byte_string(&map, x_pad.data(), x_pad.size());
    
    cbor_encode_int(&map, -3);
    std::cout << "Y-coordinate for public key: ";
    for (auto byte : y_pad) {
        std::cout << std::format("{:02x}", byte);
    }
    std::cout << std::endl;    cbor_encode_byte_string(&map, y_pad.data(), y_pad.size());

    e = cbor_encoder_close_container(&encoder, &map);
    if(e != CborNoError)
        throw std::runtime_error("Cannot close CBOR map: " + std::string(cbor_error_string(e)));

    size_t len = cbor_encoder_get_buffer_size(&encoder, buf);

    std::vector<uint8_t> out_v;

    out_v.insert(out_v.end(), buf, buf + len);

    return out_v;
}

std::vector<uint8_t> build_authenticatorMakeCredential_response(std::vector<uint8_t> &authData) {
    uint8_t buf[1024];      
    CborEncoder encoder;
    CborEncoder map;
    CborEncoder attStmt;
    cbor_encoder_init(&encoder, buf, sizeof(buf), 0);

    cbor_encoder_create_map(&encoder, &map, 3);

    // 1: fmt
    cbor_encode_uint(&map, 1);
    cbor_encode_text_stringz(&map, "none");

    // 2: authData
    cbor_encode_uint(&map, 2);
    cbor_encode_byte_string(&map, authData.data(), authData.size());

    // 3: attStmt
    cbor_encode_uint(&map, 3);
    cbor_encoder_create_map(&map, &attStmt, 0);
    cbor_encoder_close_container(&map, &attStmt);

    cbor_encoder_close_container(&encoder, &map);

    size_t len = cbor_encoder_get_buffer_size(&encoder, buf);
    std::vector<uint8_t> out;
    out.push_back(0x00);  // CTAP success byte
    out.insert(out.end(), buf, buf + len);
    return out;
}
