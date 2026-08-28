#include <cstdint>
#include <openssl/rand.h>
#include <optional>
#include <stop_token>
#include <vector>
#include <iostream>

#include "authenticate.hpp"
#include "cancellation.hpp"
#include "cbor_operations/cbor.hpp"
#include "credentials/credential.hpp"
#include "cryptography/tpm.hpp"
#include "error.hpp"
#include "cryptography/crypto.hpp"
#include "uv/src/auth.hpp"

std::vector<uint8_t> CTAPGetAssertionRequest::build_response(
    UHIDReport& r,
    std::stop_token stop,
    CredentialStore& store,
    CredentialKeyProvider& key_provider
)
{
    cancellation_point(stop);
    const auto available_credentials = store.find_for_assertion(
        rpId,
        allowList
    );
    const auto number_of_credentials = static_cast<uint32_t>(
        available_credentials.size()
    );

    userPresent = false;
    userVerified = false;
    const bool request_up = options.at("up");
    const bool request_uv = options.at("uv");
#ifdef DEBUG
    std::cout << "up: " << request_up << std::endl;
    std::cout << "uv: " << request_uv << std::endl;
#endif

    switch(assertion_interaction(request_up, request_uv)) {
        case AssertionInteraction::Verification: {
            const std::string username = get_user_name();
            const std::string procname = "vfido";

#ifdef DEBUG
                const std::string confdir = "../config";
#else
                const std::string confdir = "/etc/vfido2/config";
 #endif

            const int rc = authenticate_user(
                username, procname, confdir, stop
            );
            cancellation_point(stop);
            if(rc != 0) {
                return {
                    static_cast<uint8_t>(CTAPError::CTAP2_ERR_UV_INVALID)
                };
            }
            userVerified = true;
            userPresent = request_up;
            break;
        }
        case AssertionInteraction::Presence: {
#ifdef DEBUG
            std::cout << "Authorize passkey usage" << std::endl;
#endif
            cancellation_point(stop);
            const bool consent = collect_consent(
                "Authorize passkey usage?",
                stop
            );
            cancellation_point(stop);

            if(!consent) {
                return {static_cast<uint8_t>(CTAPError::CTAP2_ERR_OPERATION_DENIED)};
            }
            userPresent = true;
            break;
        }
        case AssertionInteraction::None:
            break;
    }

    // We do not support extensions
    // Like, at all

    // Collecting consent and checking auth (fingerpring or PIN) if needed
    if(number_of_credentials > 0) {
        auto credential = available_credentials.front();
        std::cout << "Credential found!\n";
        cancellation_point(stop);
        auto payload = generate_single_credential_payload(
            credential,
            allowList.empty() && number_of_credentials > 1
                ? std::optional<uint32_t>(number_of_credentials)
                : std::nullopt,
            stop,
            store,
            key_provider
        );
        // Do not expose continuation state until authorization, signing, and
        // the durable signature-counter update have all succeeded.
        if(number_of_credentials > 1) {
            sequence.begin(
                r.cid,
                {
                    available_credentials.begin() + 1,
                    available_credentials.end()
                }
            );
        }
        return payload;
    }

    // If it falls through, no credentials were found and we return no credentials error
    std::cout << "Credential not found!\n";
    return {static_cast<uint8_t>(CTAPError::CTAP2_ERR_NO_CREDENTIALS)};
}

std::vector<uint8_t> CTAPGetAssertionRequest::build_response_next(
    uint32_t cid,
    std::stop_token stop,
    CredentialStore& store,
    CredentialKeyProvider& key_provider
) {
    auto cred_maybe = sequence.next(cid);
    if(!cred_maybe.has_value()) {
        return {
            static_cast<uint8_t>(CTAPError::CTAP2_ERR_NOT_ALLOWED)
        };
    }
    auto cred = cred_maybe.value();
    cancellation_point(stop);
    return generate_single_credential_payload(
        cred,
        std::nullopt,
        stop,
        store,
        key_provider
    );
}

std::vector<uint8_t> CTAPGetAssertionRequest::generate_single_credential_payload(
    StoredCredential &credential,
    std::optional<uint32_t> number_of_credentials,
    std::stop_token stop,
    CredentialStore& store,
    CredentialKeyProvider& key_provider
) {
    // incrementing signCont for selected credential
    credential.signCount++;
    // TODO:
    // Sign the clientDataHash along with authData with the selected credential,
    // using the structure specified in https://www.w3.org/TR/webauthn/#assertion-signature

    // Building AuthData
    // rpIdHash
    std::vector<uint8_t> rphash = sha256(rpId);
    // Flags
    const uint8_t flags = assertion_authenticator_flags(
        userPresent,
        userVerified
    );
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
    auto signature = key_provider.sign(
        credential.id,
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
    auto payload = build_authenticatorGetAssertion_response(
        authData,
        signature,
        userVerified,
        descriptor,
        number_of_credentials
    );
    cancellation_point(stop);
    store.incrementSigCount(credential.id);
    return payload;
}
