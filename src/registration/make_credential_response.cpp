#include <cstdint>
#include <openssl/obj_mac.h>
#include <sys/types.h>
#include <tss2/tss2_esys.h>
#include <vector>
#include <openssl/rand.h>
#include <openssl/ec.h>

#include "cbor_operations/cbor.hpp"
#include "credentials/credential.hpp"
#include "error.hpp"
#include "registration/registration.hpp"
#include "cryptography/crypto.hpp"
#include "const.hpp"
#include "uhid_report.hpp"
#include "cryptography/tpm.hpp"

extern CredentialStore store;

std::vector<uint8_t> CTAPMakeCredentialRequest::build_response(UHIDReport &r) {
    if(excludeList.size() > 0) {
        for(const auto &d : excludeList) {
            if(store.has(d.id)) {
                return {static_cast<uint8_t>(CTAPError::CTAP2_ERR_CREDENTIAL_EXCLUDED)};
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

    // For now, since User Verification is not yet supported
    for(auto [name, option] : options) {
        if(name == "uv" && option == true) {
            return {static_cast<uint8_t>(CTAPError::CTAP2_ERR_UNSUPPORTED_OPTION)};
        }
    }

    // Work with pinAuth parameter

    // End work with pinAuth parameter
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
    flags |= 0x01; // Explicitly assert User Presence (UP = 1)
    // flags |= (uint8_t)options["uv"] << 2;
    flags |= 1 << 6;
    int sc = 0;

    // Building Attested Credential data
    std::vector<uint8_t> authData;
    std::vector<uint8_t> credId(32);
    RAND_bytes(credId.data(), credId.size());
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
    TpmCtx tpm;
    TpmLocalHandle primary = get_primary(tpm.ctx);
    CredentialKey key = create_credential_key(tpm.ctx, primary);
    StoredCredential credential;
    credential.id = credId;
    credential.rpId = rp.id;
    credential.signCount = 0;
    credential.userId = user.id;
    credential.alg = selected_alg;
    credential.private_blob = key.privateBlob;
    credential.public_blob = key.publicBlob;

    // Do not save dummy credentials to the store if it's a make.me.blink ping
    if (rp.id != "make.me.blink") {
        store.put(credential);
    }

    // Doing scheiße
    auto extracted_coords = extractPublic(key.publicBlob);
    auto cose_map = build_cose_key(extracted_coords[0], extracted_coords[1]);
    authData.insert(authData.end(), cose_map.begin(), cose_map.end());

    std::vector<uint8_t> payload = build_authenticatorMakeCredential_response(authData);
    return payload;
}
