#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <nlohmann/json.hpp>
#include <sys/stat.h>
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

class FakeGenerationCounter final : public StoreGenerationCounter {
public:
    explicit FakeGenerationCounter(uint64_t value = 0) : value_(value) {}

    uint64_t read() override {
        return value_;
    }

    void increment() override {
        if(failNextIncrement) {
            failNextIncrement = false;
            throw std::runtime_error("simulated counter increment failure");
        }
        if(value_ == std::numeric_limits<uint64_t>::max()) {
            throw std::overflow_error("counter overflow");
        }
        ++value_;
        ++incrementCount;
    }

    void set(uint64_t value) {
        value_ = value;
    }

    bool failNextIncrement = false;
    std::size_t incrementCount = 0;

private:
    uint64_t value_;
};

class TemporaryStore {
public:
    TemporaryStore() {
        auto name_template = (
            std::filesystem::temp_directory_path() /
            "vfido2-crypto-test-XXXXXX"
        ).string();
        std::vector<char> writable_name(
            name_template.begin(), name_template.end()
        );
        writable_name.push_back('\0');

        const char* created = ::mkdtemp(writable_name.data());
        if(created == nullptr) {
            throw std::system_error(
                errno,
                std::generic_category(),
                "mkdtemp"
            );
        }

        directory_ = created;
        path_ = directory_ / "credentials.bin";
    }

    ~TemporaryStore() {
        std::error_code error;
        std::filesystem::remove_all(directory_, error);
    }

    const std::filesystem::path& path() const {
        return path_;
    }

    const std::filesystem::path& directory() const {
        return directory_;
    }

private:
    std::filesystem::path directory_;
    std::filesystem::path path_;
};

bool contains_generated_temporary_file(
    const std::filesystem::path& directory
) {
    for(const auto& entry : std::filesystem::directory_iterator(directory)) {
        if(entry.path().filename().string().starts_with(".vfido2.tmp.") &&
           entry.path().filename() != ".vfido2.tmp.stale") {
            return true;
        }
    }
    return false;
}

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
        .id = std::vector<uint8_t>(16, 0x42),
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

void write_encrypted_json(
    const std::filesystem::path& path,
    const std::vector<uint8_t>& key,
    const nlohmann::json& value,
    uint64_t generation = 1
) {
    const std::string serialized = value.dump();
    const std::vector<uint8_t> plaintext(
        serialized.begin(), serialized.end()
    );
    const std::array<uint8_t, 12> iv{};
    std::vector<uint8_t> header{
        'V', 'F', 'I', 'D', 'O', '2', 'D', 'B', 1
    };
    for(int shift = 56; shift >= 0; shift -= 8) {
        header.push_back(static_cast<uint8_t>(generation >> shift));
    }
    header.insert(header.end(), iv.begin(), iv.end());

    auto context = openssl_make_cipher_context();
    openssl_check(
        EVP_EncryptInit_ex(
            context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr
        ),
        "test EVP_EncryptInit_ex"
    );
    openssl_check(
        EVP_CIPHER_CTX_ctrl(
            context.get(), EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr
        ),
        "test EVP_CTRL_GCM_SET_IVLEN"
    );
    openssl_check(
        EVP_EncryptInit_ex(
            context.get(), nullptr, nullptr, key.data(), iv.data()
        ),
        "test EVP_EncryptInit_ex key and IV"
    );

    std::vector<uint8_t> ciphertext(
        plaintext.size() + EVP_MAX_BLOCK_LENGTH
    );
    int ciphertext_length = 0;
    openssl_check(
        EVP_EncryptUpdate(
            context.get(),
            nullptr,
            &ciphertext_length,
            header.data(),
            openssl_checked_size(header.size(), "test envelope header")
        ),
        "test EVP_EncryptUpdate AAD"
    );
    openssl_check(
        EVP_EncryptUpdate(
            context.get(),
            ciphertext.data(),
            &ciphertext_length,
            plaintext.data(),
            openssl_checked_size(plaintext.size(), "test plaintext")
        ),
        "test EVP_EncryptUpdate"
    );

    int final_length = 0;
    openssl_check(
        EVP_EncryptFinal_ex(
            context.get(),
            ciphertext.data() + ciphertext_length,
            &final_length
        ),
        "test EVP_EncryptFinal_ex"
    );

    std::array<uint8_t, 16> tag{};
    openssl_check(
        EVP_CIPHER_CTX_ctrl(
            context.get(), EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data()
        ),
        "test EVP_CTRL_GCM_GET_TAG"
    );

    std::ofstream file(path, std::ios::binary);
    CHECK(static_cast<bool>(file));
    file.write(
        reinterpret_cast<const char *>(header.data()),
        static_cast<std::streamsize>(header.size())
    );
    file.write(
        reinterpret_cast<const char *>(ciphertext.data()),
        ciphertext_length + final_length
    );
    file.write(
        reinterpret_cast<const char *>(tag.data()),
        static_cast<std::streamsize>(tag.size())
    );
    CHECK(static_cast<bool>(file));
    file.close();
    CHECK(::chmod(path.c_str(), 0600) == 0);
}

std::vector<uint8_t> read_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    CHECK(static_cast<bool>(file));
    return {
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()
    };
}

void write_file(
    const std::filesystem::path& path,
    const std::vector<uint8_t>& contents
) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    CHECK(static_cast<bool>(file));
    file.write(
        reinterpret_cast<const char*>(contents.data()),
        static_cast<std::streamsize>(contents.size())
    );
    CHECK(static_cast<bool>(file));
    file.close();
    CHECK(::chmod(path.c_str(), 0600) == 0);
}

nlohmann::json valid_storage_entry() {
    return {
        {"id", std::string(32, 'A')},
        {"rpId", "example.com"},
        {"userId", "1011"},
        {"userName", "alice"},
        {"userDisplayName", "Alice"},
        {"alg", -7},
        {"signCount", 4U},
        {"private_blob", nlohmann::json::array({0x20, 0x21})},
        {"public_blob", nlohmann::json::array({0x30, 0x31})}
    };
}

void test_hex_decoder_rejects_malformed_input() {
    TemporaryStore temporary;
    const std::vector<uint8_t> key(32, 0x33);
    CredentialStore store(temporary.path(), key);

    CHECK(store.fromHex("00aF") == std::vector<uint8_t>({0x00, 0xAF}));

    for(const std::string_view malformed : {"0", "0G", "G0", "+1", " 1"}) {
        bool rejected = false;
        try {
            (void)store.fromHex(std::string(malformed));
        } catch(const std::invalid_argument&) {
            rejected = true;
        }
        CHECK(rejected);
    }
}

void test_invalid_blob_values_are_rejected() {
    TemporaryStore temporary;
    const std::vector<uint8_t> key(32, 0x44);

    for(const nlohmann::json& invalid_value : {
        nlohmann::json(-1),
        nlohmann::json(256),
        nlohmann::json(1.5)
    }) {
        auto entry = valid_storage_entry();
        entry["public_blob"] = nlohmann::json::array({invalid_value});
        write_encrypted_json(
            temporary.path(), key, nlohmann::json::array({entry})
        );

        CredentialStore reader(temporary.path(), key);
        bool rejected = false;
        try {
            reader.load();
        } catch(const std::runtime_error&) {
            rejected = true;
        }
        CHECK(rejected);
    }
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

void test_repeated_save_replaces_database_durably() {
    TemporaryStore temporary;
    const std::vector<uint8_t> key(32, 0xA6);
    const auto credential = make_credential();

    std::ofstream stale(temporary.directory() / ".vfido2.tmp.stale");
    CHECK(static_cast<bool>(stale));
    stale << "stale";
    stale.close();

    CredentialStore writer(temporary.path(), key);
    writer.put(credential);
    writer.incrementSigCount(credential.id);

    CredentialStore reader(temporary.path(), key);
    reader.load();
    CHECK(reader.get_by_credId(credential.id).signCount == 5);
    CHECK(!contains_generated_temporary_file(temporary.directory()));

    struct stat status{};
    CHECK(::stat(temporary.path().c_str(), &status) == 0);
    CHECK((status.st_mode & 0777) == 0600);
}

void test_failed_replacement_rolls_back_and_removes_temporary_file() {
    TemporaryStore temporary;
    const std::vector<uint8_t> key(32, 0xA7);
    CHECK(std::filesystem::create_directory(temporary.path()));

    CredentialStore writer(temporary.path(), key);
    bool rejected = false;
    try {
        writer.put(make_credential());
    } catch(const std::exception&) {
        rejected = true;
    }

    CHECK(rejected);
    CHECK(!writer.has(make_credential().id));
    CHECK(!contains_generated_temporary_file(temporary.directory()));
}

void test_signature_counter_overflow_is_rejected() {
    TemporaryStore temporary;
    const std::vector<uint8_t> key(32, 0xA8);
    auto credential = make_credential();
    credential.signCount = std::numeric_limits<uint32_t>::max();

    CredentialStore writer(temporary.path(), key);
    writer.put(credential);

    bool rejected = false;
    try {
        writer.incrementSigCount(credential.id);
    } catch(const std::overflow_error&) {
        rejected = true;
    }
    CHECK(rejected);
    CHECK(
        writer.get_by_credId(credential.id).signCount ==
        std::numeric_limits<uint32_t>::max()
    );

    CredentialStore reader(temporary.path(), key);
    reader.load();
    CHECK(
        reader.get_by_credId(credential.id).signCount ==
        std::numeric_limits<uint32_t>::max()
    );
}

void test_duplicate_credential_id_is_rejected() {
    TemporaryStore temporary;
    const std::vector<uint8_t> key(32, 0xA9);
    const auto credential = make_credential();

    CredentialStore writer(temporary.path(), key);
    writer.put(credential);

    bool rejected = false;
    try {
        writer.put(credential);
    } catch(const std::invalid_argument&) {
        rejected = true;
    }
    CHECK(rejected);
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

void test_authenticated_header_rejects_generation_tampering() {
    TemporaryStore temporary;
    const std::vector<uint8_t> key(32, 0x5B);

    CredentialStore writer(temporary.path(), key);
    writer.put(make_credential());

    auto contents = read_file(temporary.path());
    CHECK(contents.size() > 16);
    contents[16] ^= 0x01;
    write_file(temporary.path(), contents);

    CredentialStore reader(temporary.path(), key);
    bool rejected = false;
    try {
        reader.load();
    } catch(const std::runtime_error&) {
        rejected = true;
    }
    CHECK(rejected);
}

void test_rollback_is_rejected() {
    TemporaryStore temporary;
    const std::vector<uint8_t> key(32, 0x5C);
    FakeGenerationCounter counter;

    CredentialStore writer(temporary.path(), key, &counter);
    writer.put(make_credential());
    const auto old_contents = read_file(temporary.path());
    writer.incrementSigCount(make_credential().id);
    CHECK(counter.read() == 2);

    write_file(temporary.path(), old_contents);
    CredentialStore reader(temporary.path(), key, &counter);
    bool rejected = false;
    try {
        reader.load();
    } catch(const std::runtime_error&) {
        rejected = true;
    }
    CHECK(rejected);
}

void test_interrupted_commit_is_reconciled_after_authentication() {
    TemporaryStore temporary;
    const std::vector<uint8_t> key(32, 0x5D);
    FakeGenerationCounter counter;

    CredentialStore writer(temporary.path(), key, &counter);
    writer.put(make_credential());
    CHECK(counter.read() == 1);

    counter.set(0);
    CredentialStore reader(temporary.path(), key, &counter);
    reader.load();

    CHECK(counter.read() == 1);
    CHECK(counter.incrementCount == 2);
    CHECK(reader.has(make_credential().id));
}

void test_failed_counter_commit_requires_reload_and_recovers() {
    TemporaryStore temporary;
    const std::vector<uint8_t> key(32, 0x5E);
    FakeGenerationCounter counter;
    counter.failNextIncrement = true;

    CredentialStore writer(temporary.path(), key, &counter);
    bool failed = false;
    try {
        writer.put(make_credential());
    } catch(const std::runtime_error&) {
        failed = true;
    }
    CHECK(failed);
    CHECK(counter.read() == 0);
    CHECK(!writer.has(make_credential().id));

    bool refused_second_write = false;
    try {
        writer.put(make_credential());
    } catch(const std::runtime_error&) {
        refused_second_write = true;
    }
    CHECK(refused_second_write);

    CredentialStore reader(temporary.path(), key, &counter);
    reader.load();
    CHECK(counter.read() == 1);
    CHECK(reader.has(make_credential().id));
}

void test_missing_store_with_nonzero_counter_is_rejected() {
    TemporaryStore temporary;
    const std::vector<uint8_t> key(32, 0x5F);
    FakeGenerationCounter counter(1);
    CredentialStore reader(temporary.path(), key, &counter);

    bool rejected = false;
    try {
        reader.load();
    } catch(const std::runtime_error&) {
        rejected = true;
    }
    CHECK(rejected);
}

void test_insecure_file_permissions_are_rejected() {
    TemporaryStore temporary;
    const std::vector<uint8_t> key(32, 0x60);
    CredentialStore writer(temporary.path(), key);
    writer.put(make_credential());
    CHECK(::chmod(temporary.path().c_str(), 0640) == 0);

    CredentialStore reader(temporary.path(), key);
    bool rejected = false;
    try {
        reader.load();
    } catch(const std::runtime_error&) {
        rejected = true;
    }
    CHECK(rejected);
}

void test_symlink_store_is_rejected() {
    TemporaryStore temporary;
    const std::vector<uint8_t> key(32, 0x61);
    const auto target = temporary.directory() / "target.bin";
    CredentialStore writer(target, key);
    writer.put(make_credential());
    CHECK(::symlink(target.c_str(), temporary.path().c_str()) == 0);

    CredentialStore reader(temporary.path(), key);
    bool rejected = false;
    try {
        reader.load();
    } catch(const std::system_error&) {
        rejected = true;
    }
    CHECK(rejected);
}

void test_oversized_store_is_rejected_before_reading() {
    TemporaryStore temporary;
    const std::vector<uint8_t> key(32, 0x62);
    const int fd = ::open(
        temporary.path().c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
        0600
    );
    CHECK(fd >= 0);
    CHECK(::ftruncate(fd, 16 * 1024 * 1024 + 1) == 0);
    CHECK(::close(fd) == 0);

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
        test_hex_decoder_rejects_malformed_input();
        test_credential_store_round_trip();
        test_repeated_save_replaces_database_durably();
        test_failed_replacement_rolls_back_and_removes_temporary_file();
        test_signature_counter_overflow_is_rejected();
        test_duplicate_credential_id_is_rejected();
        test_invalid_blob_values_are_rejected();
        test_modified_ciphertext_is_rejected();
        test_authenticated_header_rejects_generation_tampering();
        test_rollback_is_rejected();
        test_interrupted_commit_is_reconciled_after_authentication();
        test_failed_counter_commit_requires_reload_and_recovers();
        test_missing_store_with_nonzero_counter_is_rejected();
        test_insecure_file_permissions_are_rejected();
        test_symlink_store_is_rejected();
        test_oversized_store_is_rejected_before_reading();
        test_wrong_key_size_is_rejected();
    } catch(const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }

    std::cout << "crypto tests passed\n";
    return 0;
}
