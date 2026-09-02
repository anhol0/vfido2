#include "cbor_operations/cbor.hpp"
#include "cbor_operations/cbor_utils.hpp"
#include "const.hpp"
#include "uhid_report.hpp"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <tinycbor/cbor.h>

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

template<typename Function>
void decode_response(
    const std::vector<uint8_t>& response,
    Function&& decode
) {
    CHECK(!response.empty());
    CHECK(response.front() == 0x00);
    CHECK(response.size() <= CTAPHID_MAX_PAYLOAD_SIZE);

    CborParser parser;
    CborValue root;
    cbor::check(
        cbor_parser_init(
            response.data() + 1,
            response.size() - 1,
            0,
            &parser,
            &root
        ),
        "initialize response parser"
    );
    std::forward<Function>(decode)(root);
    cbor::require_complete(parser, root, "response");
}

template<typename Function>
void decode_cbor(const std::vector<uint8_t>& encoded, Function&& decode) {
    CborParser parser;
    CborValue root;
    cbor::check(
        cbor_parser_init(
            encoded.data(),
            encoded.size(),
            0,
            &parser,
            &root
        ),
        "initialize CBOR parser"
    );
    std::forward<Function>(decode)(root);
    cbor::require_complete(parser, root, "CBOR value");
}

void test_get_info_response() {
    const auto response = build_getinfo_response();
    decode_response(response, [](CborValue& root) {
        std::set<uint64_t> keys;
        cbor::read_map(root, [&](CborValue& map) {
            const auto key = cbor::read_uint(map);
            CHECK(keys.insert(key).second);
            if(key == 1) {
                std::vector<std::string> versions;
                cbor::read_array(map, [&](CborValue& array) {
                    versions.push_back(cbor::read_text(array, 32));
                });
                CHECK(versions == std::vector<std::string>{"FIDO_2_0"});
            } else if(key == 3) {
                const auto encoded_aaguid = cbor::read_bytes(map, 16);
                CHECK(std::equal(
                    encoded_aaguid.begin(),
                    encoded_aaguid.end(),
                    aaguid.begin(),
                    aaguid.end()
                ));
            } else if(key == 4) {
                std::map<std::string, bool> options;
                cbor::read_map(map, [&](CborValue& option_map) {
                    auto name = cbor::read_text(option_map, 16);
                    CHECK(options.emplace(
                        std::move(name),
                        cbor::read_bool(option_map)
                    ).second);
                });
                CHECK(options.size() == 3);
                CHECK(options.at("rk"));
                CHECK(options.at("up"));
                CHECK(options.at("uv"));
            } else {
                cbor::skip(map);
            }
        });
        CHECK(keys == std::set<uint64_t>({1, 3, 4}));
    });
}

void test_cose_key() {
    const std::vector<uint8_t> x{0x01, 0x02};
    const std::vector<uint8_t> y(32, 0xA5);
    const auto encoded = build_cose_key(x, y);

    decode_cbor(encoded, [&](CborValue& root) {
        std::map<int64_t, int64_t> integers;
        std::map<int64_t, std::vector<uint8_t>> bytes;
        cbor::read_map(root, [&](CborValue& map) {
            const auto key = cbor::read_int(map);
            if(key == -2 || key == -3) {
                CHECK(bytes.emplace(
                    key,
                    cbor::read_bytes(map, 32)
                ).second);
            } else {
                CHECK(integers.emplace(key, cbor::read_int(map)).second);
            }
        });

        CHECK(integers.size() == 3);
        CHECK(integers.at(1) == 2);
        CHECK(integers.at(3) == -7);
        CHECK(integers.at(-1) == 1);
        CHECK(bytes.size() == 2);
        CHECK(bytes.at(-2).size() == 32);
        CHECK(bytes.at(-2)[30] == 0x01);
        CHECK(bytes.at(-2)[31] == 0x02);
        CHECK(bytes.at(-3) == y);
    });
}

void test_make_credential_response() {
    const std::vector<uint8_t> auth_data{0x10, 0x20, 0x30};
    const std::vector<uint8_t> signature{
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02
    };
    const auto response =
        build_authenticatorMakeCredential_response(auth_data, signature);

    decode_response(response, [&](CborValue& root) {
        std::set<uint64_t> keys;
        cbor::read_map(root, [&](CborValue& map) {
            const auto key = cbor::read_uint(map);
            CHECK(keys.insert(key).second);
            if(key == 1) {
                CHECK(cbor::read_text(map, 16) == "packed");
            } else if(key == 2) {
                CHECK(cbor::read_bytes(map, 64) == auth_data);
            } else if(key == 3) {
                std::set<std::string> statement_keys;
                cbor::read_map(map, [&](CborValue& statement) {
                    const auto name = cbor::read_text(statement, 16);
                    CHECK(statement_keys.insert(name).second);
                    if(name == "alg") {
                        CHECK(cbor::read_int(statement) == -7);
                    } else if(name == "sig") {
                        CHECK(cbor::read_bytes(statement, 128) == signature);
                    } else {
                        cbor::skip(statement);
                    }
                });
                CHECK(
                    statement_keys ==
                    std::set<std::string>({"alg", "sig"})
                );
            } else {
                cbor::skip(map);
            }
        });
        CHECK(keys == std::set<uint64_t>({1, 2, 3}));
    });
}

struct AssertionFields {
    std::set<uint64_t> keys;
    std::vector<uint8_t> credential_id;
    std::string credential_type;
    std::vector<uint8_t> auth_data;
    std::vector<uint8_t> signature;
    std::vector<uint8_t> user_id;
    std::string user_name;
    std::string user_display_name;
    std::optional<uint64_t> number_of_credentials;
};

AssertionFields decode_assertion(const std::vector<uint8_t>& response) {
    AssertionFields fields;
    decode_response(response, [&](CborValue& root) {
        cbor::read_map(root, [&](CborValue& map) {
            const auto key = cbor::read_uint(map);
            CHECK(fields.keys.insert(key).second);
            if(key == 1) {
                cbor::read_map(map, [&](CborValue& descriptor) {
                    const auto name = cbor::read_text(descriptor, 16);
                    if(name == "id") {
                        fields.credential_id =
                            cbor::read_bytes(descriptor, 1024);
                    } else if(name == "type") {
                        fields.credential_type =
                            cbor::read_text(descriptor, 32);
                    } else {
                        cbor::skip(descriptor);
                    }
                });
            } else if(key == 2) {
                fields.auth_data = cbor::read_bytes(map, 7609);
            } else if(key == 3) {
                fields.signature = cbor::read_bytes(map, 1024);
            } else if(key == 4) {
                cbor::read_map(map, [&](CborValue& user) {
                    const auto name = cbor::read_text(user, 32);
                    if(name == "id") {
                        fields.user_id = cbor::read_bytes(user, 64);
                    } else if(name == "name") {
                        fields.user_name = cbor::read_text(user, 7609);
                    } else if(name == "displayName") {
                        fields.user_display_name =
                            cbor::read_text(user, 7609);
                    } else {
                        cbor::skip(user);
                    }
                });
            } else if(key == 5) {
                fields.number_of_credentials = cbor::read_uint(map);
            } else {
                cbor::skip(map);
            }
        });
    });
    return fields;
}

StoredCredential assertion_credential() {
    return StoredCredential{
        .id = {0x01, 0x02},
        .rpId = "example.com",
        .userId = {0x03, 0x04},
        .userName = std::string("al\0ice", 6),
        .userDisplayName = std::string("Ali\0ce", 6),
        .alg = -7,
        .signCount = 1,
        .private_blob = {0xAA},
        .public_blob = {0xBB},
        .discoverable = true,
        .creationOrder = 1
    };
}

void test_minimal_assertion_response() {
    const std::vector<uint8_t> auth_data{0x10};
    const std::vector<uint8_t> signature{0x20};
    const auto fields = decode_assertion(
        build_authenticatorGetAssertion_response(
            auth_data,
            signature,
            false
        )
    );
    CHECK(fields.keys == std::set<uint64_t>({2, 3}));
    CHECK(fields.auth_data == auth_data);
    CHECK(fields.signature == signature);
}

void test_assertion_identity_and_map_sizes() {
    const auto credential = assertion_credential();
    const std::vector<uint8_t> auth_data{0x10};
    const std::vector<uint8_t> signature{0x20};

    auto fields = decode_assertion(
        build_authenticatorGetAssertion_response(
            auth_data,
            signature,
            false,
            &credential,
            0
        )
    );
    CHECK(fields.keys == std::set<uint64_t>({1, 2, 3, 4, 5}));
    CHECK(fields.credential_id == credential.id);
    CHECK(fields.credential_type == "public-key");
    CHECK(fields.user_id == credential.userId);
    CHECK(fields.user_name.empty());
    CHECK(fields.user_display_name.empty());
    CHECK(fields.number_of_credentials.has_value());
    CHECK(*fields.number_of_credentials == 0);

    fields = decode_assertion(
        build_authenticatorGetAssertion_response(
            auth_data,
            signature,
            true,
            &credential,
            2
        )
    );
    CHECK(fields.user_name == credential.userName);
    CHECK(fields.user_display_name == credential.userDisplayName);
    CHECK(fields.number_of_credentials.has_value());
    CHECK(*fields.number_of_credentials == 2);
}

void test_encoding_failures_are_typed() {
    bool structural_failure = false;
    try {
        static_cast<void>(build_cose_key(
            std::vector<uint8_t>(33, 0x01),
            std::vector<uint8_t>(32, 0x02)
        ));
    } catch(const CborEncodingError& error) {
        structural_failure =
            error.failure() == CborEncodingFailure::invalid_structure;
    }
    CHECK(structural_failure);

    bool resource_failure = false;
    try {
        static_cast<void>(build_authenticatorMakeCredential_response(
            std::vector<uint8_t>(CTAPHID_MAX_PAYLOAD_SIZE, 0xA5),
            std::vector<uint8_t>{0x30}
        ));
    } catch(const CborEncodingError& error) {
        resource_failure =
            error.failure() == CborEncodingFailure::resource_limit;
    }
    CHECK(resource_failure);
}

using Test = std::pair<const char*, void (*)()>;

} // namespace

int main() {
    const std::vector<Test> tests{
        {"GetInfo response", test_get_info_response},
        {"COSE key", test_cose_key},
        {"MakeCredential response", test_make_credential_response},
        {"minimal assertion response", test_minimal_assertion_response},
        {"assertion identity and map sizes", test_assertion_identity_and_map_sizes},
        {"typed encoding failures", test_encoding_failures_are_typed}
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
