#include <cstdint>
#include <openssl/rand.h>
#include <optional>
#include <vector>
#include <iostream>

#include "authenticate.hpp"
#include "cbor_operations/cbor.hpp"
#include "credentials/credential.hpp"
#include "cryptography/tpm.hpp"
#include "error.hpp"
#include "cryptography/crypto.hpp"
#include "uv/src/auth.hpp"

extern CredentialStore store;

std::vector<uint8_t> CTAPGetAssertionRequest::build_response(UHIDReport &r)
{
    // Getting number of credentials
    uint32_t number_of_credentials = 0;
    std::vector<StoredCredential> available_credentials = {};
    if(allowList.size() != 0) {
        for(auto &cred : allowList) {
            if(store.has(cred.id) && store.get_by_credId(cred.id).rpId == rpId) {
                number_of_credentials++;
                available_credentials.push_back(store.get_by_credId(cred.id));
            }
        }
    } else {
        auto &all = store.get_all_creds();
        for(auto& [id, cred] : all) {
            if(cred.rpId == rpId) {
                number_of_credentials++;
                available_credentials.push_back(cred);
            }
        }
    }

    // Caching the credentials that are available for authentication
    // They are used in authenticatorGetNextAssertion method
    cache = available_credentials;


    // No auth part for now
    // We just fake it for now, will add in the future
    for(auto [name, option] : options) {
        #ifdef DEBUG
            std::cout << name << ": " << option << std::endl;
        #endif
        if(name == "uv" && option == true) {
            const std::string username = get_user_name();
            const std::string procname = "vfido";

            #ifdef DEBUG
                const std::string confdir = "../config";
            #else
                const std::string confdir = "/etc/vfido2/config";
            #endif

            int rc = authenticate_user(username, procname, confdir);
            if(rc != 0) {
                return {static_cast<uint8_t>(CTAPError::CTAP2_ERR_UV_BLOCKED)};
            } else { break; }
        } else if (name == "uv" && option == false) {
            #ifdef DEBUG
                std::cout << "Authorize passkey usage" << std::endl;
            #endif
            bool consent = collect_consent("Authorize passkey usage?");
            if(!consent) {
                return {static_cast<uint8_t>(CTAPError::CTAP2_ERR_OPERATION_DENIED)};
            } else { break; }
        }
    }

    // We do not support extensions
    // Like, at all

    // Collecting consent and checking auth (fingerpring or PIN) if needed
    if(number_of_credentials > 0) {
        auto credential_for_authentication = cache.get_next();
        if(credential_for_authentication.has_value()) {
            std::cout << "Credential found!\n";
            // Generating payload for specific credential
            return generate_single_credential_payload(credential_for_authentication.value(), number_of_credentials);
        } else {
            return {static_cast<uint8_t>(CTAPError::CTAP2_ERR_INVALID_CREDENTIAL)};
        }
    }

    // If it falls through, no credentials were found and we return no credentials error
    std::cout << "Credential not found!\n";
    return {static_cast<uint8_t>(CTAPError::CTAP2_ERR_NO_CREDENTIALS)};
}

std::vector<uint8_t> CTAPGetAssertionRequest::build_response_next() {
    auto cred_maybe = cache.get_next();
    if(!cred_maybe.has_value()) { return {static_cast<uint8_t>(CTAPError::CTAP2_ERR_INVALID_CREDENTIAL)}; }
    auto cred = cred_maybe.value();
    return generate_single_credential_payload(cred, cache.get_size());
}

std::vector<uint8_t> CTAPGetAssertionRequest::generate_single_credential_payload(
    StoredCredential &credential,
    uint32_t number_of_credentials
) {
    // incrementing signCont for selected credential
    store.incrementSigCount(credential.id);
    credential.signCount++;
    // TODO:
    // Sign the clientDataHash along with authData with the selected credential,
    // using the structure specified in https://www.w3.org/TR/webauthn/#assertion-signature

    // Building AuthData
    // rpIdHash
    std::vector<uint8_t> rphash = sha256(rpId);
    // Flags
    uint8_t flags = 0x00;
    flags |= 0x01; // Explicitly assert User Presence (UP = 1)
    // flags |= 0x01 << 2; // Explicitly assert User Verification (UV = 1)
    flags |= options.at("uv") << 2;
    const int sc = credential.signCount;

    // Building Attested Credential data
    std::vector<uint8_t> authData;
    // Building Auth Data ctructure
    authData.insert(authData.end(), rphash.begin(), rphash.end());
    authData.push_back(flags);
    authData.push_back((sc >> 24) & 0xFF);
    authData.push_back((sc >> 16) & 0xFF);
    authData.push_back((sc >> 8)  & 0xFF);
    authData.push_back((sc >> 0)  & 0xFF);
    std::vector<uint8_t> verificaton_data = authData;
    verificaton_data.insert(verificaton_data.end(), clientDataHash.begin(), clientDataHash.end());
    auto verification_data_hash = sha256(verificaton_data);
    TpmCtx tpm;
    TpmLocalHandle primary = get_primary(tpm.ctx);
    auto signature = sign(
        tpm.ctx,
        primary,
        verification_data_hash,
        credential.public_blob,
        credential.private_blob
    );

    // If there is only 1 credential matched by the authenticator
    // Omit fields 0x01 and 0x04
    // If allowList was empty or > 1 credential was found, include these two fields must be included
    std::optional<StoredCredential> descriptor = std::nullopt;
    if(allowList.size() != 1) {
        descriptor = credential;
    }

    // Generating the payload
    auto payload = build_authenticatorGetAssertion_response(authData, signature, descriptor, number_of_credentials);
    return payload;
}
