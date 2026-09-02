#include "cbor.hpp"

#include "const.hpp"
#include "uhid_report.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <new>
#include <span>
#include <string>
#include <tinycbor/cbor.h>
#include <utility>
#include <vector>

namespace {

struct BoundedCborOutput {
    std::vector<uint8_t> bytes;
};

CborEncodingFailure classify_error(CborError error) noexcept {
    if(
        error == CborErrorOutOfMemory ||
        error == CborErrorDataTooLarge
    ) {
        return CborEncodingFailure::resource_limit;
    }
    return CborEncodingFailure::invalid_structure;
}

void check(CborError error) {
    if(error != CborNoError)
        throw CborEncodingError(classify_error(error));
}

CborError append_cbor(
    void* context,
    const void* data,
    std::size_t size,
    CborEncoderAppendType
) noexcept {
    auto& output = *static_cast<BoundedCborOutput*>(context);
    if(
        output.bytes.size() > CTAPHID_MAX_PAYLOAD_SIZE ||
        size > CTAPHID_MAX_PAYLOAD_SIZE - output.bytes.size()
    ) {
        return CborErrorDataTooLarge;
    }
    if(size == 0)
        return CborNoError;

    try {
        const auto* first = static_cast<const uint8_t*>(data);
        output.bytes.insert(output.bytes.end(), first, first + size);
        return CborNoError;
    } catch(const std::bad_alloc&) {
        return CborErrorOutOfMemory;
    } catch(...) {
        return CborErrorDataTooLarge;
    }
}

template<typename Encode>
std::vector<uint8_t> encode_cbor(bool include_success_status, Encode&& encode) {
    BoundedCborOutput output;
    try {
        if(include_success_status)
            output.bytes.push_back(0x00);
    } catch(const std::bad_alloc&) {
        throw CborEncodingError(CborEncodingFailure::resource_limit);
    }

    CborEncoder encoder;
    cbor_encoder_init_writer(&encoder, append_cbor, &output);
    try {
        std::forward<Encode>(encode)(encoder);
    } catch(const CborEncodingError&) {
        throw;
    } catch(const std::bad_alloc&) {
        throw CborEncodingError(CborEncodingFailure::resource_limit);
    }
    return std::move(output.bytes);
}

std::vector<uint8_t> pad32(std::span<const uint8_t> value) {
    if(value.size() > 32)
        throw CborEncodingError(CborEncodingFailure::invalid_structure);

    try {
        std::vector<uint8_t> result(32, 0);
        std::copy(value.begin(), value.end(), result.end() - value.size());
        return result;
    } catch(const std::bad_alloc&) {
        throw CborEncodingError(CborEncodingFailure::resource_limit);
    }
}

void encode_text(CborEncoder& encoder, const std::string& value) {
    check(cbor_encode_text_string(
        &encoder,
        value.data(),
        value.size()
    ));
}

} // namespace

CborEncodingError::CborEncodingError(CborEncodingFailure failure)
    : std::runtime_error("CBOR response encoding failed"),
      failure_(failure) {}

CborEncodingFailure CborEncodingError::failure() const noexcept {
    return failure_;
}

std::vector<uint8_t> build_getinfo_response() {
    return encode_cbor(true, [](CborEncoder& encoder) {
        CborEncoder map;
        check(cbor_encoder_create_map(&encoder, &map, 6));

        check(cbor_encode_uint(&map, 1));
        CborEncoder versions;
        check(cbor_encoder_create_array(&map, &versions, 1));
        check(cbor_encode_text_stringz(&versions, "FIDO_2_0"));
        check(cbor_encoder_close_container_checked(&map, &versions));

        check(cbor_encode_uint(&map, 3));
        check(cbor_encode_byte_string(
            &map,
            aaguid.data(),
            aaguid.size()
        ));

        check(cbor_encode_uint(&map, 4));
        CborEncoder options;
        check(cbor_encoder_create_map(&map, &options, 3));
        check(cbor_encode_text_stringz(&options, "rk"));
        check(cbor_encode_boolean(&options, true));
        check(cbor_encode_text_stringz(&options, "up"));
        check(cbor_encode_boolean(&options, true));
        check(cbor_encode_text_stringz(&options, "uv"));
        check(cbor_encode_boolean(&options, true));
        check(cbor_encoder_close_container_checked(&map, &options));

        check(cbor_encode_uint(&map, 9));
        CborEncoder transports;
        check(cbor_encoder_create_array(&map, &transports, 1));
        check(cbor_encode_text_stringz(&transports, "usb"));
        check(cbor_encoder_close_container_checked(&map, &transports));

        check(cbor_encode_uint(&map, 10));
        CborEncoder algorithms;
        check(cbor_encoder_create_array(&map, &algorithms, 1));
        CborEncoder algorithm;
        check(cbor_encoder_create_map(&algorithms, &algorithm, 2));
        check(cbor_encode_text_stringz(&algorithm, "alg"));
        check(cbor_encode_int(&algorithm, -7));
        check(cbor_encode_text_stringz(&algorithm, "type"));
        check(cbor_encode_text_stringz(&algorithm, "public-key"));
        check(cbor_encoder_close_container_checked(&algorithms, &algorithm));
        check(cbor_encoder_close_container_checked(&map, &algorithms));

        check(cbor_encode_uint(&map, 14));
        check(cbor_encode_uint(&map, firmware_version));

        check(cbor_encoder_close_container_checked(&encoder, &map));
    });
}

std::vector<uint8_t> build_cose_key(
    std::span<const uint8_t> x,
    std::span<const uint8_t> y
) {
    const auto x_padded = pad32(x);
    const auto y_padded = pad32(y);

    return encode_cbor(false, [&](CborEncoder& encoder) {
        CborEncoder map;
        check(cbor_encoder_create_map(&encoder, &map, 5));

        check(cbor_encode_int(&map, 1));
        check(cbor_encode_int(&map, 2));
        check(cbor_encode_int(&map, 3));
        check(cbor_encode_int(&map, -7));
        check(cbor_encode_int(&map, -1));
        check(cbor_encode_int(&map, 1));
        check(cbor_encode_int(&map, -2));
        check(cbor_encode_byte_string(
            &map,
            x_padded.data(),
            x_padded.size()
        ));
        check(cbor_encode_int(&map, -3));
        check(cbor_encode_byte_string(
            &map,
            y_padded.data(),
            y_padded.size()
        ));

        check(cbor_encoder_close_container_checked(&encoder, &map));
    });
}

std::vector<uint8_t> build_authenticatorMakeCredential_response(
    std::span<const uint8_t> auth_data,
    std::span<const uint8_t> signData
) {
    return encode_cbor(true, [&](CborEncoder& encoder) {
        CborEncoder map;
        check(cbor_encoder_create_map(&encoder, &map, 3));

        check(cbor_encode_uint(&map, 1));
        check(cbor_encode_text_stringz(&map, "packed"));

        check(cbor_encode_uint(&map, 2));
        check(cbor_encode_byte_string(
            &map,
            auth_data.data(),
            auth_data.size()
        ));

        check(cbor_encode_uint(&map, 3));
        CborEncoder attestation_statement;
        check(cbor_encoder_create_map(
            &map,
            &attestation_statement,
            2
        ));
        check(cbor_encode_text_stringz(
            &attestation_statement,
            "alg"
        ));
        check(cbor_encode_int(
            &attestation_statement,
            -7
        ));

        check(cbor_encode_text_stringz(
            &attestation_statement,
            "sig"
        ));
        check(cbor_encode_byte_string(
            &attestation_statement,
            signData.data(),
            signData.size()
        ));

        check(cbor_encoder_close_container_checked(
            &map,
            &attestation_statement
        ));

        check(cbor_encoder_close_container_checked(&encoder, &map));
    });
}

std::vector<uint8_t> build_authenticatorGetAssertion_response(
    std::span<const uint8_t> auth_data,
    std::span<const uint8_t> signature,
    bool uv,
    const StoredCredential* credential,
    std::optional<uint32_t> number_of_credentials
) {
    const std::size_t map_size = 2 +
        (credential != nullptr ? 2 : 0) +
        (number_of_credentials.has_value() ? 1 : 0);

    return encode_cbor(true, [&](CborEncoder& encoder) {
        CborEncoder map;
        check(cbor_encoder_create_map(&encoder, &map, map_size));

        if(credential != nullptr) {
            check(cbor_encode_uint(&map, 0x01));
            CborEncoder credential_map;
            check(cbor_encoder_create_map(&map, &credential_map, 2));
            check(cbor_encode_text_stringz(&credential_map, "id"));
            check(cbor_encode_byte_string(
                &credential_map,
                credential->id.data(),
                credential->id.size()
            ));
            check(cbor_encode_text_stringz(&credential_map, "type"));
            check(cbor_encode_text_stringz(
                &credential_map,
                "public-key"
            ));
            check(cbor_encoder_close_container_checked(
                &map,
                &credential_map
            ));
        }

        check(cbor_encode_uint(&map, 0x02));
        check(cbor_encode_byte_string(
            &map,
            auth_data.data(),
            auth_data.size()
        ));

        check(cbor_encode_uint(&map, 0x03));
        check(cbor_encode_byte_string(
            &map,
            signature.data(),
            signature.size()
        ));

        if(credential != nullptr) {
            check(cbor_encode_uint(&map, 0x04));
            CborEncoder user_map;
            check(cbor_encoder_create_map(
                &map,
                &user_map,
                uv ? 3 : 1
            ));
            check(cbor_encode_text_stringz(&user_map, "id"));
            check(cbor_encode_byte_string(
                &user_map,
                credential->userId.data(),
                credential->userId.size()
            ));

            if(uv) {
                check(cbor_encode_text_stringz(&user_map, "name"));
                encode_text(user_map, credential->userName);
                check(cbor_encode_text_stringz(
                    &user_map,
                    "displayName"
                ));
                encode_text(user_map, credential->userDisplayName);
            }
            check(cbor_encoder_close_container_checked(&map, &user_map));
        }

        if(number_of_credentials.has_value()) {
            check(cbor_encode_uint(&map, 0x05));
            check(cbor_encode_uint(&map, *number_of_credentials));
        }

        check(cbor_encoder_close_container_checked(&encoder, &map));
    });
}
