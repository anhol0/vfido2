#ifndef CBOR_HPP
#define CBOR_HPP

#include <tinycbor/cbor.h>
#include <vector>
inline std::vector<uint8_t> build_getinfo_response() {
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

    uint8_t aaguid[16] = {0};
    cbor_encode_byte_string(&map, aaguid, 16);

    // 4: options
    cbor_encode_uint(&map, 4);

    cbor_encoder_create_map(&map, &options, 2);

    cbor_encode_text_stringz(&options, "rk");
    cbor_encode_boolean(&options, true);

    cbor_encode_text_stringz(&options, "up");
    cbor_encode_boolean(&options, true);

    // cbor_encode_text_stringz(&options, "uv");
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

#endif
