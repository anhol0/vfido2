#include "registration/registration.hpp"

#include <array>
#include <cstdint>
#include <set>

#include "cbor_operations/cbor_utils.hpp"

std::optional<CTAPError>
CTAPMakeCredentialRequest::validation_error() const noexcept {
    if(up_option_present)
        return CTAPError::CTAP2_ERR_INVALID_OPTION;
    if(extensions_requested)
        return CTAPError::CTAP2_ERR_UNSUPPORTED_EXTENSION;
    if(pin_auth_present || pin_protocol_present)
        return CTAPError::CTAP2_ERR_PIN_AUTH_INVALID;
    return std::nullopt;
}

bool CTAPMakeCredentialRequest::parseRequest(
    std::vector<uint8_t>& payload
) {
    clear();

    try {
        CborParser parser;
        CborValue root;
        cbor::check(
            cbor_parser_init(
                payload.data(),
                payload.size(),
                0,
                &parser,
                &root
            ),
            "initialize MakeCredential parser"
        );

        std::set<uint64_t> seen;
        cbor::read_map(root, [&](CborValue& map) {
            const uint64_t key = cbor::read_uint(map);

            if(!seen.insert(key).second)
                throw cbor::Error("duplicate MakeCredential parameter");

            if(key < dispatch_table.size() && dispatch_table[key]) {
                (this->*dispatch_table[key])(map);
            } else {
                cbor::skip(map);
            }
        });

        constexpr std::array<uint64_t, 4> required{1, 2, 3, 4};
        for(const uint64_t key : required) {
            if(!seen.contains(key))
                throw cbor::Error("missing required MakeCredential parameter");
        }

        cbor::require_complete(parser, root, "MakeCredential request");

        return true;
    } catch(const cbor::Error&) {
        clear();
        return false;
    }
}
