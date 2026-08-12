#include "authentication/authenticate.hpp"

#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>

#include "cbor_operations/cbor_utils.hpp"

namespace {
    constexpr std::size_t CLIENT_DATA_HASH_LENGTH = 32;
    constexpr std::size_t MAX_RP_ID_LENGTH = 253;
    constexpr std::size_t MAX_ENTITY_TEXT_LENGTH = 64;
    constexpr std::size_t MAX_CREDENTIAL_ID_LENGTH = 7609;
    constexpr std::size_t MAX_EXTENSION_NAME_LENGTH = 64;
    constexpr std::size_t MAX_EXTENSION_VALUE_LENGTH = 7609;
    constexpr std::size_t MAX_TRANSPORT_NAME_LENGTH = 32;
    constexpr std::size_t MAX_PIN_AUTH_LENGTH = 64;

    void require_unique(
        std::set<std::string>& seen,
        const std::string& key,
        std::string_view context
    ) {
        if(!seen.insert(key).second) {
            throw cbor::Error(
                "duplicate " + std::string(context) + " member: " + key
            );
        }
    }

    std::optional<ExtensionValue> read_extension_value(CborValue& value) {
        ExtensionValue extension;

        if(cbor_value_is_boolean(&value)) {
            extension.type = Type::Bool;
            extension.value = cbor::read_bool(value);
        } else if(cbor_value_is_integer(&value)) {
            extension.type = Type::Int;
            extension.value = cbor::read_int(value);
        } else if(cbor_value_is_text_string(&value)) {
            extension.type = Type::String;
            extension.value = cbor::read_text(
                value,
                MAX_EXTENSION_VALUE_LENGTH
            );
        } else if(cbor_value_is_byte_string(&value)) {
            extension.type = Type::Bytes;
            extension.value = cbor::read_bytes(
                value,
                MAX_EXTENSION_VALUE_LENGTH
            );
        } else {
            // Structured extension inputs are not implemented, but unknown
            // extensions must still be consumed so parsing can continue.
            cbor::skip(value);
            return std::nullopt;
        }

        return extension;
    }

    PublicKeyCredentialDescriptor read_credential_descriptor(
        CborValue& value
    ) {
        PublicKeyCredentialDescriptor descriptor;
        std::set<std::string> seen;

        cbor::read_map(value, [&](CborValue& map) {
            const std::string key = cbor::read_text(
                map,
                MAX_ENTITY_TEXT_LENGTH
            );
            require_unique(seen, key, "credential descriptor");

            if(key == "type") {
                descriptor.type = cbor::read_text(
                    map,
                    MAX_ENTITY_TEXT_LENGTH
                );
            } else if(key == "id") {
                descriptor.id = cbor::read_bytes(
                    map,
                    MAX_CREDENTIAL_ID_LENGTH
                );
            } else if(key == "transports") {
                cbor::read_array(map, [&](CborValue& transports) {
                    descriptor.transports.push_back(cbor::read_text(
                        transports,
                        MAX_TRANSPORT_NAME_LENGTH
                    ));
                });
            } else {
                cbor::skip(map);
            }
        });

        if(
            !seen.contains("type") ||
            !seen.contains("id") ||
            descriptor.type.empty() ||
            descriptor.id.empty()
        ) {
            throw cbor::Error(
                "credential descriptor is missing a non-empty type or id"
            );
        }

        return descriptor;
    }
}

void CTAPGetAssertionRequest::parse_rp_id(CborValue& value) {
    rpId = cbor::read_text(value, MAX_RP_ID_LENGTH);
    if(rpId.empty())
        throw cbor::Error("rpId must not be empty");
}

void CTAPGetAssertionRequest::parse_client_data_hash(CborValue& value) {
    clientDataHash = cbor::read_bytes(value, CLIENT_DATA_HASH_LENGTH);
    if(clientDataHash.size() != CLIENT_DATA_HASH_LENGTH)
        throw cbor::Error("clientDataHash must contain exactly 32 bytes");
}

void CTAPGetAssertionRequest::parse_allow_list(CborValue& value) {
    cbor::read_array(value, [&](CborValue& array) {
        allowList.push_back(read_credential_descriptor(array));
    });
}

void CTAPGetAssertionRequest::parse_extensions(CborValue& value) {
    std::set<std::string> seen;

    cbor::read_map(value, [&](CborValue& map) {
        const std::string name = cbor::read_text(
            map,
            MAX_EXTENSION_NAME_LENGTH
        );
        require_unique(seen, name, "extension");

        if(auto extension = read_extension_value(map))
            extensions.emplace(name, std::move(*extension));
    });
}

void CTAPGetAssertionRequest::parse_options(CborValue& value) {
    std::set<std::string> seen;

    cbor::read_map(value, [&](CborValue& map) {
        const std::string name = cbor::read_text(
            map,
            MAX_ENTITY_TEXT_LENGTH
        );
        require_unique(seen, name, "option");

        if(name == "up" || name == "uv")
            options[name] = cbor::read_bool(map);
        else
            cbor::skip(map);
    });
}

void CTAPGetAssertionRequest::parse_pin_auth(CborValue& value) {
    pinAuth = cbor::read_bytes(value, MAX_PIN_AUTH_LENGTH);
}

void CTAPGetAssertionRequest::parse_pin_protocol(CborValue& value) {
    pinProtocol = cbor::read_uint(value);
}
