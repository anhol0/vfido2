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

    void test_valid_get_assertion_with_optional_fields() {
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
        }

        auto payload = get_assertion_request();
        CTAPGetAssertionRequest request;
        CHECK(request.parseRequest(payload));
        CHECK(!request.has_rk_option());
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
        {"valid MakeCredential", test_valid_make_credential},
        {"MakeCredential rk option", test_make_credential_parses_rk_option},
        {"MakeCredential bad hash", test_make_credential_rejects_bad_hash},
        {"MakeCredential missing nested field", test_make_credential_rejects_missing_nested_field},
        {"duplicate top-level parameter", test_duplicate_top_level_parameter_is_rejected},
        {"unknown parameter", test_unknown_parameter_is_consumed},
        {"valid GetAssertion", test_valid_get_assertion_with_optional_fields},
        {"GetAssertion wrong option type", test_get_assertion_rejects_wrong_option_type},
        {"GetAssertion rk option presence", test_get_assertion_tracks_rk_option_presence},
        {"GetAssertion wrong rk type", test_get_assertion_rejects_wrong_rk_option_type},
        {"GetAssertion empty credential ID", test_get_assertion_rejects_empty_credential_id},
        {"trailing data", test_trailing_data_is_rejected}
    };

    std::size_t failed = 0;
    for(const auto& [name, test] : tests) {
        try {
            test();
            std::cout << "PASS: " << name << '\n';
        } catch(const std::exception& error) {
            ++failed;
            std::cerr << "FAIL: " << name << ": " << error.what() << '\n';
        }
    }

    if(failed != 0) {
        std::cerr << failed << " test(s) failed\n";
        return 1;
    }

    std::cout << tests.size() << " test(s) passed\n";
    return 0;
}
