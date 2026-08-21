#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <unistd.h>

#include "credentials/credential.hpp"
#include "cryptography/crypto.hpp"

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

class TemporaryStore {
public:
    TemporaryStore()
        : path_(
              std::filesystem::temp_directory_path() /
              ("vfido2-crypto-test-" + std::to_string(getpid()) + ".bin")
          ) {
        std::error_code error;
        std::filesystem::remove(path_, error);
    }

    ~TemporaryStore() {
        std::error_code error;
        std::filesystem::remove(path_, error);
    }

    const std::filesystem::path& path() const {
        return path_;
    }

private:
    std::filesystem::path path_;
};

void test_sha256() {
    const std::string input = "abc";
    const std::array<uint8_t, 32> expected{
        0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
        0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
        0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
        0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD
    };

    const auto digest = sha256(input);
    CHECK(digest.size() == expected.size());
    CHECK(std::equal(digest.begin(), digest.end(), expected.begin()));
}

StoredCredential make_credential() {
    return StoredCredential{
        .id = {0x01, 0x02, 0x03},
        .rpId = "example.com",
        .userId = {0x10, 0x11},
        .userName = "alice",
        .userDisplayName = "Alice",
        .alg = -7,
        .signCount = 4,
        .private_blob = {0x20, 0x21},
        .public_blob = {0x30, 0x31}
    };
}

void test_credential_store_round_trip() {
    TemporaryStore temporary;
    const std::vector<uint8_t> key(32, 0xA5);
    const auto credential = make_credential();

    CredentialStore writer(temporary.path(), key);
    writer.put(credential);

    CredentialStore reader(temporary.path(), key);
    reader.load();
    const auto& loaded = reader.get_by_credId(credential.id);

    CHECK(loaded.id == credential.id);
    CHECK(loaded.rpId == credential.rpId);
    CHECK(loaded.userId == credential.userId);
    CHECK(loaded.userName == credential.userName);
    CHECK(loaded.userDisplayName == credential.userDisplayName);
    CHECK(loaded.alg == credential.alg);
    CHECK(loaded.signCount == credential.signCount);
    CHECK(loaded.private_blob == credential.private_blob);
    CHECK(loaded.public_blob == credential.public_blob);
}

void test_modified_ciphertext_is_rejected() {
    TemporaryStore temporary;
    const std::vector<uint8_t> key(32, 0x5A);

    CredentialStore writer(temporary.path(), key);
    writer.put(make_credential());

    std::fstream file(
        temporary.path(),
        std::ios::binary | std::ios::in | std::ios::out
    );
    CHECK(static_cast<bool>(file));
    file.seekg(-1, std::ios::end);
    char byte = 0;
    file.read(&byte, 1);
    CHECK(static_cast<bool>(file));
    byte ^= 0x01;
    file.seekp(-1, std::ios::end);
    file.write(&byte, 1);
    file.close();

    CredentialStore reader(temporary.path(), key);
    bool rejected = false;
    try {
        reader.load();
    } catch(const std::runtime_error&) {
        rejected = true;
    }
    CHECK(rejected);
}

void test_wrong_key_size_is_rejected() {
    TemporaryStore temporary;
    const std::vector<uint8_t> short_key(31, 0x00);

    bool rejected = false;
    try {
        CredentialStore store(temporary.path(), short_key);
    } catch(const std::invalid_argument&) {
        rejected = true;
    }
    CHECK(rejected);
}

} // namespace

int main() {
    try {
        test_sha256();
        test_credential_store_round_trip();
        test_modified_ciphertext_is_rejected();
        test_wrong_key_size_is_rejected();
    } catch(const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }

    std::cout << "crypto tests passed\n";
    return 0;
}
