#include "authenticate.hpp"
#include "cbor_operations/cbor.hpp"
#include "credentials/credential.hpp"
#include "cryptography/tpm.hpp"
#include "error.hpp"
#include <openssl/rand.h>
#include <optional>
#include "cryptography/crypto.hpp"
#include <iostream>

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

    // No auth part for now

    // Processing options parameters
    // For now, since User Verification is not yet supported
    for(auto [name, option] : options) {
        if(name == "uv" && option == true) {
            return {static_cast<uint8_t>(CTAPError::CTAP2_ERR_UNSUPPORTED_OPTION)};
        }
    }

    // We do not support extensions
    // Like, at all

    // Collecting consent and checking auth (fingerpring or PIN) if needed
    bool consent = 1;

    StoredCredential credential_for_authentication = {};
    if(number_of_credentials > 0) {
        credential_for_authentication = available_credentials[0];
        std::cout << "Credential found!\n";

        // incrementing signCont for selected credential
        store.incrementSigCount(credential_for_authentication.id);
        credential_for_authentication.signCount++;
        // TODO:
        // Sign the clientDataHash along with authData with the selected credential,
        // using the structure specified in https://www.w3.org/TR/webauthn/#assertion-signature

        // Building AuthData
        // rpIdHash
        std::vector<uint8_t> rphash = sha256(rpId);
        // Flags
        uint8_t flags = 0x00;
        flags |= 0x01; // Explicitly assert User Presence (UP = 1)
        // flags |= (uint8_t)options["uv"] << 2;
        // flags |= 1 << 6;
        int sc = credential_for_authentication.signCount;

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
            credential_for_authentication.public_blob,
            credential_for_authentication.private_blob
        );

        // If there is only 1 credential matched by the authenticator
        // Omit fields 0x01 and 0x04
        // If allowList was empty or > 1 credential was found, include these two fields must be included
        std::optional<StoredCredential> descriptor = std::nullopt;
        if(allowList.size() != 1) {
            descriptor = credential_for_authentication;
        }

        // Generating the payload
        auto payload = build_authenticatorGetAssertion_response(authData, signature, descriptor, number_of_credentials);
        return payload;
    }

    // If it falls through, no credentials were found and we return no credentials error
    std::cout << "Credential not found!\n";
    return {static_cast<uint8_t>(CTAPError::CTAP2_ERR_NO_CREDENTIALS)};
}
