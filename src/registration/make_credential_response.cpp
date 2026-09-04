#include <cstdint>
#include <openssl/obj_mac.h>
#include <stop_token>
#include <string>
#include <sys/types.h>
#include <tss2/tss2_esys.h>
#include <vector>
#include <openssl/ec.h>

#include "cancellation.hpp"
#include "cbor_operations/cbor.hpp"
#include "credentials/credential.hpp"
#include "error.hpp"
#include "registration/registration.hpp"
#include "cryptography/crypto.hpp"
#include "const.hpp"
#include "uhid_report.hpp"
#include "cryptography/tpm.hpp"
#include "uv/src/user_interaction.hpp"

std::vector<uint8_t> CTAPMakeCredentialRequest::build_response(
    UHIDReport& r,
    std::stop_token stop,
    CredentialStore& store,
    CredentialKeyProvider& key_provider,
    UserInteraction& user_interaction,
    KeepaliveState& keepalive
) {
    cancellation_point(stop);
    const UserIdentity local_user = user_interaction.current_user(stop);
    if(!excludeList.empty()) {
        for(const auto &d : excludeList) {
            if(
                d.type == "public-key" &&
                store.has_for_rp(d.id, rp.id, local_user.uid)
            ) {
                // Do not reveal that this RP already has a credential until
                // the user-presence ceremony required by CTAP has completed.
                cancellation_point(stop);
                const auto presence = user_interaction.request_presence(
                    local_user,
                    {
                        .operation = UserInteractionOperation::check_excluded_credential,
                        .relyingPartyId = rp.id
                    },
                    stop,
                    keepalive
                );
                cancellation_point(stop);
                if(presence != UserInteractionResult::approved) {
                    return {
                        static_cast<uint8_t>(
                            CTAPError::CTAP2_ERR_OPERATION_DENIED
                        )
                    };
                }
                return {
                    static_cast<uint8_t>(
                        CTAPError::CTAP2_ERR_CREDENTIAL_EXCLUDED
                    )
                };
            }
        }
    }

    // Algorithm check
    // For now only ES256 algorithm is supported (https://ldapwiki.com/wiki/Wiki.jsp?page=ES256)
    int selected_alg = 0;
    for(const auto &param : publicKeyCredParams) {
        if(param.alg == -7 && param.type == "public-key") {
            selected_alg = param.alg;
            break;
        }
    }

    if(selected_alg == 0) {
        return {static_cast<uint8_t>(CTAPError::CTAP2_ERR_UNSUPPORTED_ALGORITHM)};
    }

    if(const auto error = validation_error()) {
        return {static_cast<uint8_t>(*error)};
    }

    // User Verification
    // Not cryptographically secure, but fine for now
    for(auto [name, option] : options) {
        if(name == "uv" && option == true) {
            const auto verification = user_interaction.request_verification(
                local_user,
                {
                    .operation = UserInteractionOperation::make_credential,
                    .relyingPartyId = rp.id
                },
                stop,
                keepalive
            );
            cancellation_point(stop);
            if(verification != UserInteractionResult::approved) {
                return {static_cast<uint8_t>(CTAPError::CTAP2_ERR_UV_BLOCKED)};
            } else { break; }
        } else if (name == "uv" && option == false) {
            cancellation_point(stop);
            const auto presence = user_interaction.request_presence(
                local_user,
                {
                    .operation = UserInteractionOperation::make_credential,
                    .relyingPartyId = rp.id
                },
                stop,
                keepalive
            );
            cancellation_point(stop);

            if(presence != UserInteractionResult::approved) {
                return {static_cast<uint8_t>(CTAPError::CTAP2_ERR_OPERATION_DENIED)};
            } else { break; }
        }
    }

    // Authentication Data is a blob:
    // rpIdHash (32 bytes)
    // flags (1 byte)
    // signCount (4 bytes, big-endian)
    // aaguid (16 bytes)                last 3 are "attestedCredentialData"
    // credIdLen (2 bytes)
    // credId (N bytes)
    // COSE public key

    // rpIdHash
    std::vector<uint8_t> rphash = sha256(rp.id);

    // Flags
    uint8_t flags = 0x00;
    flags |= 0x01; // MakeCredential always requires user presence in CTAP 2.0.
    flags |= options.at("uv") << 2;
    flags |= 1 << 6; // Attested Credential Data
    int sc = 0;

    // Building Attested Credential data
    std::vector<uint8_t> authData;
    std::vector<uint8_t> credId(32);
    openssl_random_bytes(credId);
    uint16_t credIdLen = (uint16_t)credId.size();
    uint8_t credIdLenBytes[2] = {
        (uint8_t)(credIdLen >> 8),
        (uint8_t)(credIdLen >> 0)
    };

    // building Auth Data ctructure
    authData.insert(authData.end(), rphash.begin(), rphash.end());
    authData.push_back(flags);
    authData.push_back((sc >> 24) & 0xFF);
    authData.push_back((sc >> 16) & 0xFF);
    authData.push_back((sc >> 8)  & 0xFF);
    authData.push_back((sc >> 0)  & 0xFF);
    authData.insert(authData.end(), aaguid.begin(), aaguid.begin() + 16);
    authData.push_back(credIdLenBytes[0]);
    authData.push_back(credIdLenBytes[1]);
    authData.insert(authData.end(), credId.begin(), credId.end());

    // Generating the keypair and storing the credential
    cancellation_point(stop);
    CredentialKey key = key_provider.create(credId);
    cancellation_point(stop);

    StoredCredential credential;
    credential.id = credId;
    credential.rpId = rp.id;
    credential.signCount = 0;
    credential.userId = user.id;
    credential.userName = user.name;
    credential.userDisplayName = user.displayName;
    credential.alg = selected_alg;
    credential.private_blob = key.privateBlob;
    credential.public_blob = key.publicBlob;
    credential.discoverable = options.at("rk");

    // Doing scheiße
    auto extracted_coords = extractPublic(key.publicBlob);
    auto cose_map = build_cose_key(extracted_coords[0], extracted_coords[1]);
    authData.insert(authData.end(), cose_map.begin(), cose_map.end());

    // Creating signData and signing it with private key
    std::vector<uint8_t> signDataRaw(authData);
    signDataRaw.insert(signDataRaw.end(), clientDataHash.begin(), clientDataHash.end());
    auto signDataHash = sha256(signDataRaw);
    auto signData = key_provider.sign(credId, signDataHash, key.publicBlob, key.privateBlob);

    std::vector<uint8_t> payload = build_authenticatorMakeCredential_response(authData, signData);

    cancellation_point(stop);

    // Do not save dummy credentials to the store if it's a make.me.blink ping
    if (rp.id != "make.me.blink" && rp.id != ".dummy") {
        cancellation_point(stop);
        store.put(credential, local_user.uid);
    }
    return payload;
}
