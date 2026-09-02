#include "registration/registration.hpp"

#include <limits>
#include <set>
#include <string>
#include <string_view>
#include <utility>

#include "cbor_operations/cbor_utils.hpp"

namespace {
    constexpr std::size_t CLIENT_DATA_HASH_LENGTH = 32;
    constexpr std::size_t MAX_RP_ID_LENGTH = 253;
    constexpr std::size_t MAX_ENTITY_TEXT_LENGTH = 64;
    constexpr std::size_t MAX_USER_ID_LENGTH = 64;
    constexpr std::size_t MAX_CREDENTIAL_ID_LENGTH = 7609;
    constexpr std::size_t MAX_EXTENSION_NAME_LENGTH = 64;
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

void CTAPMakeCredentialRequest::parse_client_data_hash(CborValue& value) {
    clientDataHash = cbor::read_bytes(value, CLIENT_DATA_HASH_LENGTH);
    if(clientDataHash.size() != CLIENT_DATA_HASH_LENGTH)
        throw cbor::Error("clientDataHash must contain exactly 32 bytes");
}

void CTAPMakeCredentialRequest::parse_rp(CborValue& value) {
    std::set<std::string> seen;

    cbor::read_map(value, [&](CborValue& map) {
        const std::string key = cbor::read_text(
            map,
            MAX_ENTITY_TEXT_LENGTH
        );
        require_unique(seen, key, "relying-party entity");

        if(key == "id") {
            rp.id = cbor::read_text(map, MAX_RP_ID_LENGTH);
        } else if(key == "name") {
            rp.name = cbor::read_text(map, MAX_ENTITY_TEXT_LENGTH);
        } else {
            cbor::skip(map);
        }
    });

    if(!seen.contains("id") || rp.id.empty())
        throw cbor::Error("relying-party entity is missing a non-empty id");
}

void CTAPMakeCredentialRequest::parse_user(CborValue& value) {
    std::set<std::string> seen;

    cbor::read_map(value, [&](CborValue& map) {
        const std::string key = cbor::read_text(
            map,
            MAX_ENTITY_TEXT_LENGTH
        );
        require_unique(seen, key, "user entity");

        if(key == "id") {
            user.id = cbor::read_bytes(map, MAX_USER_ID_LENGTH);
        } else if(key == "name") {
            user.name = cbor::read_text(map, MAX_ENTITY_TEXT_LENGTH);
        } else if(key == "displayName") {
            user.displayName = cbor::read_text(
                map,
                MAX_ENTITY_TEXT_LENGTH
            );
        } else {
            cbor::skip(map);
        }
    });

    if(!seen.contains("id"))
        throw cbor::Error("user entity is missing id");
}

void CTAPMakeCredentialRequest::parse_pubkey_params(CborValue& value) {
    cbor::read_array(value, [&](CborValue& array) {
        PubKeyCredParam parameter;
        std::set<std::string> seen;

        cbor::read_map(array, [&](CborValue& map) {
            const std::string key = cbor::read_text(
                map,
                MAX_ENTITY_TEXT_LENGTH
            );
            require_unique(seen, key, "public-key parameter");

            if(key == "type") {
                parameter.type = cbor::read_text(
                    map,
                    MAX_ENTITY_TEXT_LENGTH
                );
            } else if(key == "alg") {
                const int64_t algorithm = cbor::read_int(map);
                if(
                    algorithm < std::numeric_limits<int>::min() ||
                    algorithm > std::numeric_limits<int>::max()
                ) {
                    throw cbor::Error("public-key algorithm is out of range");
                }
                parameter.alg = static_cast<int>(algorithm);
            } else {
                cbor::skip(map);
            }
        });

        if(!seen.contains("type") || !seen.contains("alg")) {
            throw cbor::Error(
                "public-key parameter is missing type or alg"
            );
        }

        publicKeyCredParams.push_back(std::move(parameter));
    });
}

void CTAPMakeCredentialRequest::parse_exclude_list(CborValue& value) {
    cbor::read_array(value, [&](CborValue& array) {
        excludeList.push_back(read_credential_descriptor(array));
    });
}

void CTAPMakeCredentialRequest::parse_extensions(CborValue& value) {
    std::set<std::string> seen;

    cbor::read_map(value, [&](CborValue& map) {
        const std::string name = cbor::read_text(
            map,
            MAX_EXTENSION_NAME_LENGTH
        );
        require_unique(seen, name, "extension");
        // CTAP2.0 requires unsupported extensions to be ignored.
        cbor::skip(map);
    });
}

void CTAPMakeCredentialRequest::parse_options(CborValue& value) {
    std::set<std::string> seen;

    cbor::read_map(value, [&](CborValue& map) {
        const std::string name = cbor::read_text(
            map,
            MAX_ENTITY_TEXT_LENGTH
        );
        require_unique(seen, name, "option");

        if(name == "rk" || name == "uv") {
            options[name] = cbor::read_bool(map);
        } else if(name == "up") {
            (void)cbor::read_bool(map);
            up_option_present = true;
        } else {
            cbor::skip(map);
        }
    });
}

void CTAPMakeCredentialRequest::parse_pin_auth(CborValue& value) {
    (void)cbor::read_bytes(value, MAX_PIN_AUTH_LENGTH);
    pin_auth_present = true;
}

void CTAPMakeCredentialRequest::parse_pin_protocol(CborValue& value) {
    (void)cbor::read_uint(value);
    pin_protocol_present = true;
}
