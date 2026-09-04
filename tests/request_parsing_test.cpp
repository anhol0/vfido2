#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "authentication/authenticate.hpp"
#include "registration/registration.hpp"
#include "test_runner.hpp"

namespace {
    void check(bool condition, const char* expression, int line) {
        if(!condition) {
            throw std::runtime_error(
                "CHECK failed at line " + std::to_string(line) +
                ": " + expression
            );
        }
    }

#define CHECK(expression) check((expression), #expression, __LINE__)

    void append_unsigned(std::vector<uint8_t>& output, uint8_t value) {
        if(value >= 24)
            throw std::runtime_error("test encoder only supports small integers");
        output.push_back(value);
    }

    void append_map(std::vector<uint8_t>& output, uint8_t members) {
        if(members >= 24)
            throw std::runtime_error("test encoder only supports small maps");
        output.push_back(static_cast<uint8_t>(0xA0 | members));
    }

    void append_array(std::vector<uint8_t>& output, uint8_t members) {
        if(members >= 24)
            throw std::runtime_error("test encoder only supports small arrays");
        output.push_back(static_cast<uint8_t>(0x80 | members));
    }

    void append_text(std::vector<uint8_t>& output, const std::string& value) {
        if(value.size() >= 24)
            throw std::runtime_error("test encoder only supports short strings");
        output.push_back(static_cast<uint8_t>(0x60 | value.size()));
        output.insert(output.end(), value.begin(), value.end());
    }

    void append_bytes(
        std::vector<uint8_t>& output,
        std::size_t length,
        uint8_t byte = 0xA5
    ) {
        if(length < 24) {
            output.push_back(static_cast<uint8_t>(0x40 | length));
        } else if(length <= 0xFF) {
            output.push_back(0x58);
            output.push_back(static_cast<uint8_t>(length));
        } else {
            throw std::runtime_error("test encoder only supports short bytes");
        }
        output.insert(output.end(), length, byte);
    }

    void append_credential_descriptor(
        std::vector<uint8_t>& output,
        std::size_t id_length = 3
    ) {
        append_map(output, 3);
        append_text(output, "type");
        append_text(output, "public-key");
        append_text(output, "id");
        append_bytes(output, id_length, 0x11);
        append_text(output, "transports");
        append_array(output, 1);
        append_text(output, "usb");
    }

    std::vector<uint8_t> make_credential_request(
        std::size_t hash_length = 32,
        bool include_rp_id = true,
        uint8_t outer_members = 4
    ) {
        std::vector<uint8_t> payload;
        append_map(payload, outer_members);

        append_unsigned(payload, 1);
        append_bytes(payload, hash_length);

        append_unsigned(payload, 2);
        append_map(payload, include_rp_id ? 2 : 1);
        if(include_rp_id) {
            append_text(payload, "id");
            append_text(payload, "example.com");
        }
        append_text(payload, "name");
        append_text(payload, "Example");

        append_unsigned(payload, 3);
        append_map(payload, 3);
        append_text(payload, "id");
        append_bytes(payload, 4, 0x42);
        append_text(payload, "name");
        append_text(payload, "alice");
        append_text(payload, "displayName");
        append_text(payload, "Alice");

        append_unsigned(payload, 4);
        append_array(payload, 1);
        append_map(payload, 2);
        append_text(payload, "type");
        append_text(payload, "public-key");
        append_text(payload, "alg");
        payload.push_back(0x26); // -7 (ES256)

        return payload;
    }

    std::vector<uint8_t> get_assertion_request(
        std::size_t hash_length = 32,
        uint8_t outer_members = 2
    ) {
        std::vector<uint8_t> payload;
        append_map(payload, outer_members);
        append_unsigned(payload, 1);
        append_text(payload, "example.com");
        append_unsigned(payload, 2);
        append_bytes(payload, hash_length);
        return payload;
    }

    void test_valid_make_credential() {
        auto payload = make_credential_request();
        CTAPMakeCredentialRequest request;

        CHECK(request.parseRequest(payload));
        CHECK(request.clientDataHash.size() == 32);
        CHECK(request.rp.id == "example.com");
        CHECK(request.user.id.size() == 4);
        CHECK(request.user.name == "alice");
        CHECK(request.user.displayName == "Alice");
        CHECK(request.publicKeyCredParams.size() == 1);
        CHECK(request.publicKeyCredParams.front().type == "public-key");
        CHECK(request.publicKeyCredParams.front().alg == -7);
        CHECK(!request.options.at("rk"));
    }

    void test_make_credential_parses_rk_option() {
        auto payload = make_credential_request(32, true, 5);
        append_unsigned(payload, 7);
        append_map(payload, 1);
        append_text(payload, "rk");
        payload.push_back(0xF5); // true

        CTAPMakeCredentialRequest request;
        CHECK(request.parseRequest(payload));
        CHECK(request.options.at("rk"));
        CHECK(!request.validation_error().has_value());
    }

    void test_make_credential_rejects_up_option() {
        for(const uint8_t value : {uint8_t{0xF4}, uint8_t{0xF5}}) {
            auto payload = make_credential_request(32, true, 5);
            append_unsigned(payload, 7);
            append_map(payload, 1);
            append_text(payload, "up");
            payload.push_back(value);

            CTAPMakeCredentialRequest request;
            CHECK(request.parseRequest(payload));
            CHECK(
                request.validation_error() ==
                CTAPError::CTAP2_ERR_INVALID_OPTION
            );
        }
    }

    void test_make_credential_ignores_unsupported_extensions() {
        for(const bool structured : {false, true}) {
            auto payload = make_credential_request(32, true, 5);
            append_unsigned(payload, 6);
            append_map(payload, 1);
            append_text(payload, "exampleExtension");
            if(structured) {
                append_array(payload, 1);
                append_unsigned(payload, 1);
            } else {
                payload.push_back(0xF5); // true
            }

            CTAPMakeCredentialRequest request;
            CHECK(request.parseRequest(payload));
            CHECK(!request.validation_error().has_value());
        }

        auto payload = make_credential_request(32, true, 5);
        append_unsigned(payload, 6);
        append_map(payload, 0);
        CTAPMakeCredentialRequest request;
        CHECK(request.parseRequest(payload));
        CHECK(!request.validation_error().has_value());
    }

    void test_make_credential_rejects_malformed_extensions() {
        auto duplicate = make_credential_request(32, true, 5);
        append_unsigned(duplicate, 6);
        append_map(duplicate, 2);
        append_text(duplicate, "duplicate");
        duplicate.push_back(0xF5); // true
        append_text(duplicate, "duplicate");
        duplicate.push_back(0xF4); // false

        CTAPMakeCredentialRequest request;
        CHECK(!request.parseRequest(duplicate));

        auto non_text_key = make_credential_request(32, true, 5);
        append_unsigned(non_text_key, 6);
        append_map(non_text_key, 1);
        append_unsigned(non_text_key, 1);
        non_text_key.push_back(0xF5); // true
        CHECK(!request.parseRequest(non_text_key));
    }

    void test_make_credential_rejects_pin_parameters() {
        for(const uint8_t key : {uint8_t{8}, uint8_t{9}}) {
            auto payload = make_credential_request(32, true, 5);
            append_unsigned(payload, key);
            if(key == 8) {
                append_bytes(payload, 16, 0x24);
            } else {
                append_unsigned(payload, 1);
            }

            CTAPMakeCredentialRequest request;
            CHECK(request.parseRequest(payload));
            CHECK(
                request.validation_error() ==
                CTAPError::CTAP2_ERR_PIN_AUTH_INVALID
            );
        }

        auto payload = make_credential_request(32, true, 6);
        append_unsigned(payload, 8);
        append_bytes(payload, 16, 0x24);
        append_unsigned(payload, 9);
        append_unsigned(payload, 1);
        CTAPMakeCredentialRequest request;
        CHECK(request.parseRequest(payload));
        CHECK(
            request.validation_error() ==
            CTAPError::CTAP2_ERR_PIN_AUTH_INVALID
        );
    }

    void test_unknown_options_are_ignored() {
        auto make_payload = make_credential_request(32, true, 5);
        append_unsigned(make_payload, 7);
        append_map(make_payload, 1);
        append_text(make_payload, "futureOption");
        append_map(make_payload, 1);
        append_text(make_payload, "value");
        make_payload.push_back(0xF5); // true

        CTAPMakeCredentialRequest make_request;
        CHECK(make_request.parseRequest(make_payload));
        CHECK(!make_request.validation_error().has_value());

        auto assertion_payload = get_assertion_request(32, 3);
        append_unsigned(assertion_payload, 5);
        append_map(assertion_payload, 1);
        append_text(assertion_payload, "futureOption");
        append_array(assertion_payload, 1);
        append_unsigned(assertion_payload, 1);

        CTAPGetAssertionRequest assertion_request;
        CHECK(assertion_request.parseRequest(assertion_payload));
        CHECK(!assertion_request.validation_error().has_value());
    }

    void test_make_credential_rejects_bad_hash() {
        auto payload = make_credential_request(31);
        CTAPMakeCredentialRequest request;
        CHECK(!request.parseRequest(payload));
        CHECK(request.clientDataHash.empty());
    }

    void test_make_credential_rejects_missing_nested_field() {
        auto payload = make_credential_request(32, false);
        CTAPMakeCredentialRequest request;
        CHECK(!request.parseRequest(payload));
        CHECK(request.rp.id.empty());
    }

    void test_duplicate_top_level_parameter_is_rejected() {
        auto payload = make_credential_request(32, true, 5);
        append_unsigned(payload, 1);
        append_bytes(payload, 32);

        CTAPMakeCredentialRequest request;
        CHECK(!request.parseRequest(payload));
    }

    void test_unknown_parameter_is_consumed() {
        auto payload = make_credential_request(32, true, 5);
        append_unsigned(payload, 10);
        append_array(payload, 2);
        append_unsigned(payload, 1);
        append_map(payload, 1);
        append_text(payload, "nested");
        payload.push_back(0xF5); // true

        CTAPMakeCredentialRequest request;
        CHECK(request.parseRequest(payload));
    }

    void test_get_assertion_unsupported_field_priority() {
        auto payload = get_assertion_request(32, 7);

        append_unsigned(payload, 3);
        append_array(payload, 1);
        append_credential_descriptor(payload);

        append_unsigned(payload, 4);
        append_map(payload, 2);
        append_text(payload, "exampleExtension");
        payload.push_back(0xF5); // true
        append_text(payload, "structuredExtension");
        append_array(payload, 2);
        append_unsigned(payload, 1);
        append_unsigned(payload, 2);

        append_unsigned(payload, 5);
        append_map(payload, 3);
        append_text(payload, "up");
        payload.push_back(0xF4); // false
        append_text(payload, "uv");
        payload.push_back(0xF5); // true
        append_text(payload, "futureOption");
        append_map(payload, 1);
        append_text(payload, "value");
        payload.push_back(0xF5); // true

        append_unsigned(payload, 6);
        append_bytes(payload, 16, 0x24);
        append_unsigned(payload, 7);
        append_unsigned(payload, 1);

        CTAPGetAssertionRequest request;
        CHECK(request.parseRequest(payload));
        CHECK(
            request.validation_error() ==
            CTAPError::CTAP2_ERR_PIN_AUTH_INVALID
        );
    }

    void test_get_assertion_ignores_unsupported_extensions() {
        for(const bool structured : {false, true}) {
            auto payload = get_assertion_request(32, 3);
            append_unsigned(payload, 4);
            append_map(payload, 1);
            append_text(payload, "exampleExtension");
            if(structured) {
                append_map(payload, 1);
                append_text(payload, "nested");
                payload.push_back(0xF5); // true
            } else {
                payload.push_back(0xF5); // true
            }

            CTAPGetAssertionRequest request;
            CHECK(request.parseRequest(payload));
            CHECK(!request.validation_error().has_value());
        }

        auto payload = get_assertion_request(32, 3);
        append_unsigned(payload, 4);
        append_map(payload, 0);
        CTAPGetAssertionRequest request;
        CHECK(request.parseRequest(payload));
        CHECK(!request.validation_error().has_value());
    }

    void test_get_assertion_rejects_malformed_extensions() {
        auto duplicate = get_assertion_request(32, 3);
        append_unsigned(duplicate, 4);
        append_map(duplicate, 2);
        append_text(duplicate, "duplicate");
        duplicate.push_back(0xF5); // true
        append_text(duplicate, "duplicate");
        duplicate.push_back(0xF4); // false

        CTAPGetAssertionRequest request;
        CHECK(!request.parseRequest(duplicate));

        auto non_text_key = get_assertion_request(32, 3);
        append_unsigned(non_text_key, 4);
        append_map(non_text_key, 1);
        append_unsigned(non_text_key, 1);
        non_text_key.push_back(0xF5); // true
        CHECK(!request.parseRequest(non_text_key));
    }

    void test_get_assertion_rejects_pin_parameters() {
        for(const uint8_t key : {uint8_t{6}, uint8_t{7}}) {
            auto payload = get_assertion_request(32, 3);
            append_unsigned(payload, key);
            if(key == 6) {
                append_bytes(payload, 16, 0x24);
            } else {
                append_unsigned(payload, 1);
            }

            CTAPGetAssertionRequest request;
            CHECK(request.parseRequest(payload));
            CHECK(
                request.validation_error() ==
                CTAPError::CTAP2_ERR_PIN_AUTH_INVALID
            );
        }
    }

    void test_get_assertion_rejects_wrong_option_type() {
        auto payload = get_assertion_request(32, 3);
        append_unsigned(payload, 5);
        append_map(payload, 1);
        append_text(payload, "uv");
        append_unsigned(payload, 1);

        CTAPGetAssertionRequest request;
        CHECK(!request.parseRequest(payload));
    }

    void test_get_assertion_tracks_rk_option_presence() {
        for(const uint8_t value : {uint8_t{0xF4}, uint8_t{0xF5}}) {
            auto payload = get_assertion_request(32, 3);
            append_unsigned(payload, 5);
            append_map(payload, 1);
            append_text(payload, "rk");
            payload.push_back(value);

            CTAPGetAssertionRequest request;
            CHECK(request.parseRequest(payload));
            CHECK(request.has_rk_option());
            CHECK(
                request.validation_error() ==
                CTAPError::CTAP2_ERR_INVALID_OPTION
            );
        }

        auto payload = get_assertion_request();
        CTAPGetAssertionRequest request;
        CHECK(request.parseRequest(payload));
        CHECK(!request.has_rk_option());
        CHECK(!request.validation_error().has_value());
    }

    void test_unsupported_state_is_cleared() {
        auto make_unsupported = make_credential_request(32, true, 5);
        append_unsigned(make_unsupported, 7);
        append_map(make_unsupported, 1);
        append_text(make_unsupported, "up");
        make_unsupported.push_back(0xF4); // false

        CTAPMakeCredentialRequest make_request;
        CHECK(make_request.parseRequest(make_unsupported));
        CHECK(make_request.validation_error().has_value());

        auto make_valid = make_credential_request();
        CHECK(make_request.parseRequest(make_valid));
        CHECK(!make_request.validation_error().has_value());

        auto unsupported = get_assertion_request(32, 3);
        append_unsigned(unsupported, 6);
        append_bytes(unsupported, 16, 0x24);

        CTAPGetAssertionRequest request;
        CHECK(request.parseRequest(unsupported));
        CHECK(request.validation_error().has_value());

        auto valid = get_assertion_request();
        CHECK(request.parseRequest(valid));
        CHECK(!request.validation_error().has_value());
    }

    void test_get_assertion_rejects_wrong_rk_option_type() {
        auto payload = get_assertion_request(32, 3);
        append_unsigned(payload, 5);
        append_map(payload, 1);
        append_text(payload, "rk");
        append_unsigned(payload, 1);

        CTAPGetAssertionRequest request;
        CHECK(!request.parseRequest(payload));
        CHECK(!request.has_rk_option());
    }

    void test_get_assertion_rejects_empty_credential_id() {
        auto payload = get_assertion_request(32, 3);
        append_unsigned(payload, 3);
        append_array(payload, 1);
        append_credential_descriptor(payload, 0);

        CTAPGetAssertionRequest request;
        CHECK(!request.parseRequest(payload));
    }

    StoredCredential assertion_credential(uint8_t id_byte) {
        return StoredCredential{
            .id = std::vector<uint8_t>(16, id_byte),
            .ownerUid = 1000,
            .rpId = "example.com",
            .userId = {id_byte},
            .userName = "alice",
            .userDisplayName = "Alice",
            .alg = -7,
            .signCount = 0,
            .private_blob = {0x01},
            .public_blob = {0x02}
        };
    }

    UserContext local_user_context(uint32_t uid = 1000) {
        return {
            .uid = uid,
            .name = uid == 1000 ? "alice" : "bob",
            .session = std::nullopt
        };
    }

    UserContext session_user_context(
        std::string session_id = "session-1",
        std::string interaction_agent_id = ":1.42",
        uint64_t generation = 7
    ) {
        return {
            .uid = 1000,
            .name = "alice",
            .session = UserSessionContext{
                .sessionId = std::move(session_id),
                .interactionAgentId = std::move(interaction_agent_id),
                .generation = generation
            }
        };
    }

    void test_assertion_interaction_and_flags() {
        CHECK(
            assertion_interaction(false, false) ==
            AssertionInteraction::None
        );
        CHECK(
            assertion_interaction(true, false) ==
            AssertionInteraction::Presence
        );
        CHECK(
            assertion_interaction(false, true) ==
            AssertionInteraction::Verification
        );
        CHECK(
            assertion_interaction(true, true) ==
            AssertionInteraction::Verification
        );

        CHECK(assertion_authenticator_flags(false, false) == 0x00);
        CHECK(assertion_authenticator_flags(true, false) == 0x01);
        CHECK(assertion_authenticator_flags(false, true) == 0x04);
        CHECK(assertion_authenticator_flags(true, true) == 0x05);

        CHECK(!has_assertion_continuations(true, 0));
        CHECK(!has_assertion_continuations(true, 1));
        CHECK(has_assertion_continuations(true, 2));
        CHECK(!has_assertion_continuations(false, 2));
    }

    void test_assertion_sequence_channel_timeout_and_exhaustion() {
        constexpr uint32_t origin_cid = 0x01020304;
        constexpr uint32_t foreign_cid = 0x05060708;
        const auto start = AssertionSequence::Clock::time_point{};
        const auto user_context = local_user_context();
        AssertionSequence sequence;
        sequence.begin(
            origin_cid,
            user_context,
            {assertion_credential(0x11), assertion_credential(0x22)},
            start
        );

        CHECK(!sequence.next(foreign_cid, user_context, start).has_value());
        CHECK(sequence.origin_cid() == origin_cid);

        const auto first = sequence.next(
            origin_cid,
            user_context,
            start + std::chrono::seconds(30)
        );
        CHECK(first.has_value());
        CHECK(first->id == std::vector<uint8_t>(16, 0x11));
        CHECK(sequence.origin_cid() == origin_cid);

        const auto second = sequence.next(
            origin_cid,
            user_context,
            start + std::chrono::seconds(60)
        );
        CHECK(second.has_value());
        CHECK(second->id == std::vector<uint8_t>(16, 0x22));
        CHECK(sequence.origin_cid() == 0);
        CHECK(!sequence.next(origin_cid, user_context, start).has_value());

        sequence.begin(
            origin_cid,
            user_context,
            {assertion_credential(0x33)},
            start
        );
        CHECK(
            !sequence.next(
                origin_cid,
                user_context,
                start + std::chrono::seconds(31)
            ).has_value()
        );
        CHECK(sequence.origin_cid() == 0);

        sequence.begin(
            origin_cid,
            user_context,
            {assertion_credential(0x44)},
            start
        );
        CHECK(
            !sequence.next(
                origin_cid,
                local_user_context(1001),
                start
            ).has_value()
        );
        CHECK(sequence.origin_cid() == 0);

        auto foreign_credential = assertion_credential(0x55);
        foreign_credential.ownerUid = 1001;
        bool mixed_owner_rejected = false;
        try {
            sequence.begin(
                origin_cid,
                user_context,
                {std::move(foreign_credential)},
                start
            );
        } catch(const std::invalid_argument&) {
            mixed_owner_rejected = true;
        }
        CHECK(mixed_owner_rejected);
        CHECK(sequence.origin_cid() == 0);
    }

    void test_assertion_sequence_is_bound_to_user_session() {
        constexpr uint32_t origin_cid = 0x01020304;
        const auto start = AssertionSequence::Clock::time_point{};
        const auto original_context = session_user_context();
        const std::vector<UserContext> changed_contexts{
            session_user_context("session-2", ":1.42", 7),
            session_user_context("session-1", ":1.43", 7),
            session_user_context("session-1", ":1.42", 8),
            local_user_context()
        };

        for(const auto& changed_context : changed_contexts) {
            AssertionSequence sequence;
            sequence.begin(
                origin_cid,
                original_context,
                {assertion_credential(0x66)},
                start
            );
            CHECK(
                !sequence.next(
                    origin_cid,
                    changed_context,
                    start
                ).has_value()
            );
            CHECK(sequence.origin_cid() == 0);
        }

        AssertionSequence sequence;
        sequence.begin(
            origin_cid,
            original_context,
            {assertion_credential(0x77)},
            start
        );
        CHECK(sequence.next(origin_cid, original_context, start).has_value());
    }

    void test_trailing_data_is_rejected() {
        auto payload = get_assertion_request();
        payload.push_back(0xF5);

        CTAPGetAssertionRequest request;
        CHECK(!request.parseRequest(payload));
    }

    using Test = std::pair<const char*, std::function<void()>>;
}

int main() {
    const std::vector<Test> tests{
        {"test_valid_make_credential", test_valid_make_credential},
        {"test_make_credential_parses_rk_option", test_make_credential_parses_rk_option},
        {"test_make_credential_rejects_up_option", test_make_credential_rejects_up_option},
        {"test_make_credential_ignores_unsupported_extensions", test_make_credential_ignores_unsupported_extensions},
        {"test_make_credential_rejects_malformed_extensions", test_make_credential_rejects_malformed_extensions},
        {"test_make_credential_rejects_pin_parameters", test_make_credential_rejects_pin_parameters},
        {"test_unknown_options_are_ignored", test_unknown_options_are_ignored},
        {"test_make_credential_rejects_bad_hash", test_make_credential_rejects_bad_hash},
        {"test_make_credential_rejects_missing_nested_field", test_make_credential_rejects_missing_nested_field},
        {"test_duplicate_top_level_parameter_is_rejected", test_duplicate_top_level_parameter_is_rejected},
        {"test_unknown_parameter_is_consumed", test_unknown_parameter_is_consumed},
        {"test_get_assertion_unsupported_field_priority", test_get_assertion_unsupported_field_priority},
        {"test_get_assertion_ignores_unsupported_extensions", test_get_assertion_ignores_unsupported_extensions},
        {"test_get_assertion_rejects_malformed_extensions", test_get_assertion_rejects_malformed_extensions},
        {"test_get_assertion_rejects_pin_parameters", test_get_assertion_rejects_pin_parameters},
        {"test_get_assertion_rejects_wrong_option_type", test_get_assertion_rejects_wrong_option_type},
        {"test_get_assertion_tracks_rk_option_presence", test_get_assertion_tracks_rk_option_presence},
        {"test_get_assertion_rejects_wrong_rk_option_type", test_get_assertion_rejects_wrong_rk_option_type},
        {"test_unsupported_state_is_cleared", test_unsupported_state_is_cleared},
        {"test_get_assertion_rejects_empty_credential_id", test_get_assertion_rejects_empty_credential_id},
        {"test_assertion_interaction_and_flags", test_assertion_interaction_and_flags},
        {"test_assertion_sequence_channel_timeout_and_exhaustion", test_assertion_sequence_channel_timeout_and_exhaustion},
        {"test_assertion_sequence_is_bound_to_user_session", test_assertion_sequence_is_bound_to_user_session},
        {"test_trailing_data_is_rejected", test_trailing_data_is_rejected}
    };

    test_support::Runner runner;
    for(const auto& [name, test] : tests)
        runner.run(name, test);
    return runner.finish();
}
