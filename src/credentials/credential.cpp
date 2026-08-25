#include "credential.hpp"
#include "cryptography/crypto.hpp"
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <nlohmann/json.hpp>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

class UniqueFd {
public:
    explicit UniqueFd(int fd = -1) noexcept : fd_(fd) {}

    ~UniqueFd() {
        if(fd_ >= 0) {
            ::close(fd_);
        }
    }

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    UniqueFd(UniqueFd&& other) noexcept : fd_(other.release()) {}

    UniqueFd& operator=(UniqueFd&& other) noexcept {
        if(this != &other) {
            reset(other.release());
        }
        return *this;
    }

    [[nodiscard]] int get() const noexcept {
        return fd_;
    }

    [[nodiscard]] int release() noexcept {
        return std::exchange(fd_, -1);
    }

    void reset(int fd = -1) noexcept {
        if(fd_ >= 0) {
            ::close(fd_);
        }
        fd_ = fd;
    }

private:
    int fd_;
};

class TemporaryFile {
public:
    TemporaryFile(int directory_fd, std::string&& name) noexcept
        : directory_fd_(directory_fd), name_(std::move(name)) {}

    ~TemporaryFile() {
        if(active_) {
            ::unlinkat(directory_fd_, name_.c_str(), 0);
        }
    }

    TemporaryFile(const TemporaryFile&) = delete;
    TemporaryFile& operator=(const TemporaryFile&) = delete;

    void dismiss() noexcept {
        active_ = false;
    }

    [[nodiscard]] const std::string& name() const noexcept {
        return name_;
    }

private:
    int directory_fd_;
    std::string name_;
    bool active_ = true;
};

[[noreturn]] void throw_system_error(int error, std::string operation) {
    throw std::system_error(
        error,
        std::generic_category(),
        std::move(operation)
    );
}

void close_checked(UniqueFd& fd, std::string_view description) {
    const int raw_fd = fd.release();
    if(raw_fd < 0) {
        throw std::logic_error("Attempted to close an invalid file descriptor");
    }

    if(::close(raw_fd) == -1) {
        const int error = errno;
        throw_system_error(error, "close " + std::string(description));
    }
}

void fsync_checked(int fd, std::string_view description) {
    while(::fsync(fd) == -1) {
        const int error = errno;
        if(error == EINTR) {
            continue;
        }
        throw_system_error(error, "fsync " + std::string(description));
    }
}

void write_all(int fd, std::span<const uint8_t> bytes) {
    std::size_t offset = 0;
    while(offset < bytes.size()) {
        const auto remaining = bytes.size() - offset;
        const auto chunk_size = std::min(
            remaining,
            static_cast<std::size_t>(
                std::numeric_limits<ssize_t>::max()
            )
        );

        const ssize_t written = ::write(
            fd,
            bytes.data() + offset,
            chunk_size
        );
        if(written == -1) {
            const int error = errno;
            if(error == EINTR) {
                continue;
            }
            throw_system_error(error, "write temporary credential store");
        }
        if(written == 0) {
            throw std::runtime_error(
                "write temporary credential store made no progress"
            );
        }
        offset += static_cast<std::size_t>(written);
    }
}

std::string random_temporary_name() {
    std::array<uint8_t, 16> random_bytes{};
    openssl_random_bytes(random_bytes);

    constexpr char hex_digits[] = "0123456789abcdef";
    std::string name = ".vfido2.tmp.";
    name.reserve(name.size() + random_bytes.size() * 2);
    for(const uint8_t byte : random_bytes) {
        name.push_back(hex_digits[byte >> 4]);
        name.push_back(hex_digits[byte & 0x0F]);
    }
    return name;
}

std::pair<UniqueFd, std::string> create_temporary_file(int directory_fd) {
    constexpr int maximum_attempts = 16;
    for(int attempt = 0; attempt < maximum_attempts; ++attempt) {
        auto name = random_temporary_name();
        const int fd = ::openat(
            directory_fd,
            name.c_str(),
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            S_IRUSR | S_IWUSR
        );
        if(fd >= 0) {
            return {UniqueFd(fd), std::move(name)};
        }

        const int error = errno;
        if(error != EEXIST) {
            throw_system_error(error, "create temporary credential store");
        }
    }

    throw std::runtime_error(
        "Could not create a unique temporary credential store"
    );
}

void validate_credential(const StoredCredential& credential) {
    if(credential.id.size() < 16) {
        throw std::invalid_argument(
            "Credential ID must contain at least 16 bytes"
        );
    }
    if(credential.rpId.empty()) {
        throw std::invalid_argument("Relying Party ID must not be empty");
    }
    if(credential.userId.empty() || credential.userId.size() > 64) {
        throw std::invalid_argument(
            "User ID must contain between 1 and 64 bytes"
        );
    }
    if(credential.alg != -7) {
        throw std::invalid_argument("Unsupported credential algorithm");
    }
    if(credential.private_blob.empty()) {
        throw std::invalid_argument("Private credential blob must not be empty");
    }
    if(credential.public_blob.empty()) {
        throw std::invalid_argument("Public credential blob must not be empty");
    }
}

std::filesystem::path prepare_store_directory(
    const std::filesystem::path& store_path
) {
    auto directory = store_path.parent_path();
    if(directory.empty()) {
        directory = ".";
    }

    std::error_code error;
    const bool created = std::filesystem::create_directories(directory, error);
    if(error) {
        throw std::filesystem::filesystem_error(
            "create credential store directory",
            directory,
            error
        );
    }

    if(created) {
        std::filesystem::permissions(
            directory,
            std::filesystem::perms::owner_all,
            std::filesystem::perm_options::replace,
            error
        );
        if(error) {
            throw std::filesystem::filesystem_error(
                "set credential store directory permissions",
                directory,
                error
            );
        }
    }

    return directory;
}

UniqueFd open_store_directory(const std::filesystem::path& directory) {
    const int fd = ::open(
        directory.c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    );
    if(fd == -1) {
        const int error = errno;
        throw_system_error(
            error,
            "open credential store directory " + directory.string()
        );
    }

    struct stat status{};
    if(::fstat(fd, &status) == -1) {
        const int error = errno;
        ::close(fd);
        throw_system_error(error, "inspect credential store directory");
    }
    if(!S_ISDIR(status.st_mode)) {
        ::close(fd);
        throw std::runtime_error("Credential store parent is not a directory");
    }
    if((status.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        ::close(fd);
        throw std::runtime_error(
            "Credential store directory must not be writable by group or others"
        );
    }

    return UniqueFd(fd);
}

void atomic_write_file(
    const std::filesystem::path& store_path,
    std::span<const uint8_t> contents
) {
    const auto filename = store_path.filename();
    if(filename.empty() || filename == "." || filename == "..") {
        throw std::invalid_argument(
            "Credential store path must include a valid filename"
        );
    }

    const auto directory_path = prepare_store_directory(store_path);
    auto directory = open_store_directory(directory_path);
    auto [output, temporary_name] = create_temporary_file(directory.get());
    TemporaryFile temporary(directory.get(), std::move(temporary_name));

    write_all(output.get(), contents);
    fsync_checked(output.get(), "temporary credential store");
    close_checked(output, "temporary credential store");

    int rename_result;
    do {
        rename_result = ::renameat(
            directory.get(),
            temporary.name().c_str(),
            directory.get(),
            filename.c_str()
        );
    } while(rename_result == -1 && errno == EINTR);

    if(rename_result == -1) {
        const int error = errno;
        throw_system_error(error, "replace credential store");
    }

    temporary.dismiss();
    fsync_checked(directory.get(), "credential store directory");
    close_checked(directory, "credential store directory");
}

uint8_t decode_hex_digit(char digit) {
    if(digit >= '0' && digit <= '9')
        return static_cast<uint8_t>(digit - '0');
    if(digit >= 'a' && digit <= 'f')
        return static_cast<uint8_t>(digit - 'a' + 10);
    if(digit >= 'A' && digit <= 'F')
        return static_cast<uint8_t>(digit - 'A' + 10);

    throw std::invalid_argument("Invalid hexadecimal character");
}

std::vector<uint8_t> read_byte_array(
    const nlohmann::json& entry,
    std::string_view field_name
) {
    const auto& value = entry.at(field_name);
    if(!value.is_array()) {
        throw std::runtime_error(
            std::string(field_name) + " is not a byte array"
        );
    }

    std::vector<uint8_t> bytes;
    bytes.reserve(value.size());
    for(const auto& element : value) {
        if(!element.is_number_unsigned()) {
            throw std::runtime_error(
                std::string(field_name) +
                " contains a value that is not an unsigned integer"
            );
        }

        const auto number = element.get<uint64_t>();
        if(number > std::numeric_limits<uint8_t>::max()) {
            throw std::runtime_error(
                std::string(field_name) + " contains a value above 255"
            );
        }
        bytes.push_back(static_cast<uint8_t>(number));
    }
    return bytes;
}

} // namespace

CredentialStore::CredentialStore(std::filesystem::path path, Key key) : storePath_(path), storeKey_(key) {
    if(storeKey_.size() != 32) {
        throw std::invalid_argument("Credential store key must be 32 bytes");
    }
}

// Hex conversions
std::string CredentialStore::toHex(const std::vector<uint8_t> &v) const {
    std::string s;
    s.reserve(v.size() * 2);
    for(const auto &c : v) {
        char buf[3];
        sprintf(buf, "%02X", c);
        s += buf;
    }
    return s;
}

std::vector<uint8_t> CredentialStore::fromHex(const std::string &s) {
    std::vector<uint8_t> v;
    v.reserve(s.size() / 2);
    if(s.size() % 2) throw std::invalid_argument("Odd size string is given");
    for(std::size_t i = 0; i < s.size(); i += 2) {
        const uint8_t high = decode_hex_digit(s[i]);
        const uint8_t low = decode_hex_digit(s[i + 1]);
        v.push_back(static_cast<uint8_t>((high << 4) | low));
    }
    return v;
}

// Cryptography
std::vector<uint8_t> CredentialStore::decrypt(std::vector<uint8_t> &ciphertext) {
    if(ciphertext.size() < 28) throw std::runtime_error("Ciphertext is too short");
    const uint8_t *iv = ciphertext.data();
    const uint8_t *tag = ciphertext.data() + 12;
    const uint8_t *cipher = ciphertext.data() + 28;
    const int ctlen = openssl_checked_size(
        ciphertext.size() - 28,
        "credential ciphertext"
    );

    auto context = openssl_make_cipher_context();
    openssl_check(
        EVP_DecryptInit_ex(
            context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr
        ),
        "EVP_DecryptInit_ex"
    );
    openssl_check(
        EVP_CIPHER_CTX_ctrl(
            context.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr
        ),
        "EVP_CTRL_GCM_SET_IVLEN"
    );
    openssl_check(
        EVP_DecryptInit_ex(
            context.get(), nullptr, nullptr, storeKey_.data(), iv
        ),
        "EVP_DecryptInit_ex key and IV"
    );
    openssl_check(
        EVP_CIPHER_CTX_ctrl(
            context.get(),
            EVP_CTRL_GCM_SET_TAG,
            16,
            const_cast<uint8_t *>(tag)
        ),
        "EVP_CTRL_GCM_SET_TAG"
    );

    std::vector<uint8_t> plain(
        static_cast<std::size_t>(ctlen) + EVP_MAX_BLOCK_LENGTH
    );
    int outl = 0;
    openssl_check(
        EVP_DecryptUpdate(
            context.get(), plain.data(), &outl, cipher, ctlen
        ),
        "EVP_DecryptUpdate"
    );
    int finlen = 0;
    openssl_check(
        EVP_DecryptFinal_ex(context.get(), plain.data() + outl, &finlen),
        "EVP_DecryptFinal_ex (GCM authentication failed)"
    );

    plain.resize(outl + finlen);
    return plain;
}

std::vector<uint8_t> CredentialStore::encrypt(std::vector<uint8_t> &plaintext) {
    std::vector<uint8_t> iv(12);
    openssl_random_bytes(iv);
    auto context = openssl_make_cipher_context();
    openssl_check(
        EVP_EncryptInit_ex(
            context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr
        ),
        "EVP_EncryptInit_ex"
    );
    openssl_check(
        EVP_CIPHER_CTX_ctrl(
            context.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr
        ),
        "EVP_CTRL_GCM_SET_IVLEN"
    );
    openssl_check(
        EVP_EncryptInit_ex(
            context.get(), nullptr, nullptr, storeKey_.data(), iv.data()
        ),
        "EVP_EncryptInit_ex key and IV"
    );

    std::vector<uint8_t> cipher(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int outl = 0;
    openssl_check(
        EVP_EncryptUpdate(
            context.get(),
            cipher.data(),
            &outl,
            plaintext.data(),
            openssl_checked_size(plaintext.size(), "credential plaintext")
        ),
        "EVP_EncryptUpdate"
    );
    int final_len = 0;
    openssl_check(
        EVP_EncryptFinal_ex(context.get(), cipher.data() + outl, &final_len),
        "EVP_EncryptFinal_ex"
    );

    std::vector<uint8_t> tag(16);
    openssl_check(
        EVP_CIPHER_CTX_ctrl(
            context.get(), EVP_CTRL_GCM_GET_TAG, 16, tag.data()
        ),
        "EVP_CTRL_GCM_GET_TAG"
    );

    std::vector<uint8_t> out;
    out.insert(out.end(), iv.begin(), iv.end());
    out.insert(out.end(), tag.begin(), tag.end());
    out.insert(out.end(), cipher.begin(), cipher.begin() + outl + final_len);
    return out;
}

// Saving credentials to the file
void CredentialStore::save_storage(const Storage& storage) {
    using namespace nlohmann;
    json j = json::array();
    for(const auto& item : storage) {
        const auto& cred = item.second;
        j.push_back({
            {"id", toHex(cred.id)},
            {"rpId", cred.rpId},
            {"userId", toHex(cred.userId)},
            {"userName", cred.userName},
            {"userDisplayName", cred.userDisplayName},
            {"alg", cred.alg},
            {"signCount", cred.signCount},
            {"private_blob", cred.private_blob},
            {"public_blob", cred.public_blob}
        });
    }
    std::string plaintext = j.dump();
    std::vector<uint8_t> plain(plaintext.begin(), plaintext.end());
    auto encrypted = encrypt(plain);
    atomic_write_file(storePath_, encrypted);
}

void CredentialStore::save() {
    save_storage(stored_);
}

CredentialStore::Storage CredentialStore::parse_storage(const nlohmann::json &json) {
    if(!json.is_array()) throw std::runtime_error("Storage is not an array");
    Storage loaded;

    for(const auto &entry : json) {
        if (!entry.is_object()) throw std::runtime_error("Storage entry is not an object");
        StoredCredential cred;
        cred.id = fromHex(entry.at("id").get<std::string>());
        if(cred.id.size() < 16) throw std::runtime_error("Invalid Credential ID");

        cred.rpId = entry.at("rpId").get<std::string>();
        if(cred.rpId.empty()) throw std::runtime_error("Empty Relying Party ID");

        cred.userId = fromHex(entry.at("userId").get<std::string>());
        if(cred.userId.empty() || cred.userId.size() > 64) throw std::runtime_error("Invalid User ID");

        cred.userName = entry.at("userName").get<std::string>();
        cred.userDisplayName = entry.at("userDisplayName").get<std::string>();

        cred.alg = entry.at("alg").get<int>();
        if(cred.alg != -7) throw std::runtime_error("Invalid encryption alrogithm");

        const auto &signCountValue = entry.at("signCount");
        if(!signCountValue.is_number_unsigned()) throw std::runtime_error("Invalid Sign Count type");

        const auto count = signCountValue.get<uint64_t>();
        if(count > std::numeric_limits<uint32_t>::max()) throw std::runtime_error("Sign Count out of range");
        cred.signCount = static_cast<uint32_t>(count);

        cred.public_blob = read_byte_array(entry, "public_blob");
        cred.private_blob = read_byte_array(entry, "private_blob");
        validate_credential(cred);

        const auto credential_id = toHex(cred.id);
        if(!loaded.emplace(credential_id, std::move(cred)).second)
            throw std::runtime_error("Duplicate Credential ID");
    }
    return loaded;
}

void CredentialStore::load() {
    using namespace nlohmann;
    if(!std::filesystem::exists(storePath_)) return;

    std::ifstream f(storePath_, std::ios::binary);
    std::vector<uint8_t> enc_blob(
            (std::istreambuf_iterator<char>(f)),
            std::istreambuf_iterator<char>()
    );
    auto plain = decrypt(enc_blob);
    json j = json::parse(plain.begin(), plain.end());

    auto loaded = parse_storage(j);
    stored_.swap(loaded);
}

// Public API

bool CredentialStore::has(const std::vector<uint8_t> &credId) const {
    return stored_.count(toHex(credId)) > 0;
}

void CredentialStore::put(const StoredCredential &cred) {
    validate_credential(cred);
    const auto credential_id = toHex(cred.id);
    if(stored_.contains(credential_id)) {
        throw std::invalid_argument("Credential ID already exists");
    }

    auto updated = stored_;
    updated.emplace(credential_id, cred);
    save_storage(updated);
    stored_.swap(updated);
}


const StoredCredential& CredentialStore::get_by_credId(const std::vector<uint8_t> &credId) const {
    return stored_.at(toHex(credId));
}

const CredentialStore::Storage CredentialStore::get_all_creds() const
{
    return stored_;
}

void CredentialStore::incrementSigCount(const std::vector<uint8_t> &credId) {
    const auto credential_id = toHex(credId);
    const auto current = stored_.find(credential_id);
    if(current == stored_.end()) {
        throw std::out_of_range("Credential ID was not found");
    }
    if(current->second.signCount == std::numeric_limits<uint32_t>::max()) {
        throw std::overflow_error("Signature counter cannot be incremented");
    }

    auto updated = stored_;
    ++updated.at(credential_id).signCount;
    save_storage(updated);
    stored_.swap(updated);
}
