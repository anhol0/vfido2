#include <cstdint>
#include <openssl/rand.h>
#include <optional>
#include <stop_token>
#include <vector>

#include "authenticate.hpp"
#include "cancellation.hpp"
#include "cbor_operations/cbor.hpp"
#include "credentials/credential.hpp"
#include "cryptography/tpm.hpp"
#include "error.hpp"
#include "cryptography/crypto.hpp"
#include "uv/src/user_interaction.hpp"

std::vector<uint8_t> CTAPGetAssertionRequest::build_response(
    UHIDReport& r,
    std::stop_token stop,
    CredentialStore& store,
    CredentialKeyProvider& key_provider,
    UserInteraction& user_interaction,
    KeepaliveState& keepalive
)
{
    cancellation_point(stop);
    const UserContext user_context = user_interaction.current_context(stop);
    const auto available_credentials = store.find_for_assertion(
        rpId,
        allowList,
        user_context.uid
    );
    const auto number_of_credentials = static_cast<uint32_t>(
        available_credentials.size()
    );

    if(const auto error = validation_error()) {
        return {static_cast<uint8_t>(*error)};
    }

    userPresent = false;
    userVerified = false;
    const bool request_up = options.at("up");
    const bool request_uv = options.at("uv");
    const bool has_continuations = has_assertion_continuations(
        allowList.empty(),
        available_credentials.size()
    );
    switch(assertion_interaction(request_up, request_uv)) {
        case AssertionInteraction::Verification: {
            const auto verification = user_interaction.request_verification(
                user_context,
                {
                    .operation = UserInteractionOperation::get_assertion,
                    .relyingPartyId = rpId
                },
                stop,
                keepalive
            );
            cancellation_point(stop);
            if(verification == UserInteractionResult::cancelled) {
                return {
                    static_cast<uint8_t>(
                        CTAPError::CTAP2_ERR_OPERATION_DENIED
                    )
                };
            }
            if(verification != UserInteractionResult::approved) {
                return {
                    static_cast<uint8_t>(CTAPError::CTAP2_ERR_UV_INVALID)
                };
            }
            userVerified = true;
            userPresent = request_up;
            break;
        }
        case AssertionInteraction::Presence: {
            cancellation_point(stop);
            const auto presence = user_interaction.request_presence(
                user_context,
                {
                    .operation = UserInteractionOperation::get_assertion,
                    .relyingPartyId = rpId
                },
                stop,
                keepalive
            );
            cancellation_point(stop);

            if(presence == UserInteractionResult::cancelled) {
                return {
                    static_cast<uint8_t>(
                        CTAPError::CTAP2_ERR_OPERATION_DENIED
                    )
                };
            }
            if(presence != UserInteractionResult::approved) {
                return {static_cast<uint8_t>(CTAPError::CTAP2_ERR_OPERATION_DENIED)};
            }
            userPresent = true;
            break;
        }
        case AssertionInteraction::None:
            break;
    }

    // Collecting consent and checking auth (fingerpring or PIN) if needed
    if(number_of_credentials > 0) {
        auto credential = available_credentials.front();
        cancellation_point(stop);
        auto payload = generate_single_credential_payload(
            credential,
            user_context.uid,
            has_continuations
                ? std::optional<uint32_t>(number_of_credentials)
                : std::nullopt,
            stop,
            store,
            key_provider
        );
        // Do not expose continuation state until authorization, signing, and
        // the durable signature-counter update have all succeeded.
        if(has_continuations) {
            sequence.begin(
                r.cid,
                user_context,
                {
                    available_credentials.begin() + 1,
                    available_credentials.end()
                }
            );
        }
        return payload;
    }

    // If it falls through, no credentials were found and we return no credentials error
    return {static_cast<uint8_t>(CTAPError::CTAP2_ERR_NO_CREDENTIALS)};
}

std::vector<uint8_t> CTAPGetAssertionRequest::build_response_next(
    uint32_t cid,
    std::stop_token stop,
    CredentialStore& store,
    CredentialKeyProvider& key_provider,
    UserInteraction& user_interaction
) {
    const UserContext user_context = user_interaction.current_context(stop);
    auto cred_maybe = sequence.next(cid, user_context);
    if(!cred_maybe.has_value()) {
        return {
            static_cast<uint8_t>(CTAPError::CTAP2_ERR_NOT_ALLOWED)
        };
    }
    auto cred = cred_maybe.value();
    cancellation_point(stop);
    return generate_single_credential_payload(
        cred,
        user_context.uid,
        std::nullopt,
        stop,
        store,
        key_provider
    );
}

std::vector<uint8_t> CTAPGetAssertionRequest::generate_single_credential_payload(
    StoredCredential &credential,
    uint32_t owner_uid,
    std::optional<uint32_t> number_of_credentials,
    std::stop_token stop,
    CredentialStore& store,
    CredentialKeyProvider& key_provider
) {
    // incrementing signCont for selected credential
    credential.signCount++;

    // Building AuthData
    // rpIdHash
    std::vector<uint8_t> rphash = sha256(rpId);
    // Flags
    const uint8_t flags = assertion_authenticator_flags(
        userPresent,
        userVerified
    );
    const uint32_t sc = credential.signCount;

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
    const StoredCredential* descriptor =
        allowList.size() != 1 ? &credential : nullptr;

    // Generating the payload
    auto payload = build_authenticatorGetAssertion_response(
        authData,
        signature,
        userVerified,
        descriptor,
        number_of_credentials
    );
    cancellation_point(stop);
    store.incrementSigCount(credential.id, owner_uid);
    return payload;
}
