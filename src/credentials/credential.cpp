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
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace {

constexpr std::array<uint8_t, 8> STORE_MAGIC{
    'V', 'F', 'I', 'D', 'O', '2', 'D', 'B'
};
constexpr uint8_t STORE_FORMAT_VERSION = 1;
constexpr std::size_t GENERATION_SIZE = 8;
constexpr std::size_t NONCE_SIZE = 12;
constexpr std::size_t TAG_SIZE = 16;
constexpr std::size_t HEADER_SIZE =
    STORE_MAGIC.size() + 1 + GENERATION_SIZE + NONCE_SIZE;
constexpr std::size_t MAX_STORE_SIZE = 16 * 1024 * 1024;
constexpr std::size_t MAX_CREDENTIALS = 4096;
constexpr std::size_t MAX_CREDENTIAL_BLOB_SIZE = 4096;

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

std::vector<uint8_t> read_all(int fd, std::size_t size) {
    std::vector<uint8_t> contents(size);
    std::size_t offset = 0;
    while(offset < contents.size()) {
        const ssize_t count = ::read(
            fd,
            contents.data() + offset,
            contents.size() - offset
        );
        if(count == -1) {
            const int error = errno;
            if(error == EINTR) {
                continue;
            }
            throw_system_error(error, "read credential store");
        }
        if(count == 0) {
            throw std::runtime_error(
                "Credential store was truncated while reading"
            );
        }
        offset += static_cast<std::size_t>(count);
    }
    return contents;
}

void append_uint64_be(std::vector<uint8_t>& output, uint64_t value) {
    for(int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<uint8_t>(value >> shift));
    }
}

uint64_t read_uint64_be(std::span<const uint8_t, GENERATION_SIZE> bytes) {
    uint64_t value = 0;
    for(const uint8_t byte : bytes) {
        value = (value << 8) | byte;
    }
    return value;
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
    if(credential.id.size() < 16 || credential.id.size() > 1024) {
        throw std::invalid_argument(
            "Credential ID must contain between 16 and 1024 bytes"
        );
    }
    if(credential.rpId.empty() || credential.rpId.size() > 253) {
        throw std::invalid_argument(
            "Relying Party ID must contain between 1 and 253 bytes"
        );
    }
    if(credential.userId.empty() || credential.userId.size() > 64) {
        throw std::invalid_argument(
            "User ID must contain between 1 and 64 bytes"
        );
    }
    if(credential.alg != -7) {
        throw std::invalid_argument("Unsupported credential algorithm");
    }
    if(
        credential.private_blob.empty() ||
        credential.private_blob.size() > MAX_CREDENTIAL_BLOB_SIZE
    ) {
        throw std::invalid_argument("Invalid private credential blob size");
    }
    if(
        credential.public_blob.empty() ||
        credential.public_blob.size() > MAX_CREDENTIAL_BLOB_SIZE
    ) {
        throw std::invalid_argument("Invalid public credential blob size");
    }
    if(credential.creationOrder == 0) {
        throw std::invalid_argument("Credential creation order must be non-zero");
    }
}

std::filesystem::path prepare_store_directory(
    const std::filesystem::path& store_path
) {
    auto directory = store_path.parent_path();
    if(directory.empty()) {
        directory = ".";
    }

    if(::mkdir(directory.c_str(), 0700) == -1 && errno != EEXIST) {
        throw_system_error(errno, "create credential store directory");
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
    if(status.st_uid != ::geteuid()) {
        ::close(fd);
        throw std::runtime_error(
            "Credential store directory must be owned by the service user"
        );
    }
    if((status.st_mode & 0777) != 0700) {
        ::close(fd);
        throw std::runtime_error(
            "Credential store directory permissions must be 0700"
        );
    }

    return UniqueFd(fd);
}

std::optional<std::vector<uint8_t>> read_store_file(
    const std::filesystem::path& store_path
) {
    const auto filename = store_path.filename();
    if(filename.empty() || filename == "." || filename == "..") {
        throw std::invalid_argument(
            "Credential store path must include a valid filename"
        );
    }

    auto directory_path = store_path.parent_path();
    if(directory_path.empty()) {
        directory_path = ".";
    }

    const int directory_fd = ::open(
        directory_path.c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    );
    if(directory_fd == -1 && errno == ENOENT) {
        return std::nullopt;
    }
    if(directory_fd == -1) {
        throw_system_error(errno, "open credential store directory");
    }
    UniqueFd directory(directory_fd);

    struct stat directory_status{};
    if(::fstat(directory.get(), &directory_status) == -1) {
        throw_system_error(errno, "inspect credential store directory");
    }
    if(!S_ISDIR(directory_status.st_mode)) {
        throw std::runtime_error("Credential store parent is not a directory");
    }
    if(directory_status.st_uid != ::geteuid()) {
        throw std::runtime_error(
            "Credential store directory must be owned by the service user"
        );
    }
    if((directory_status.st_mode & 0777) != 0700) {
        throw std::runtime_error(
            "Credential store directory permissions must be 0700"
        );
    }

    const int file_fd = ::openat(
        directory.get(),
        filename.c_str(),
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW
    );
    if(file_fd == -1 && errno == ENOENT) {
        return std::nullopt;
    }
    if(file_fd == -1) {
        throw_system_error(errno, "open credential store");
    }
    UniqueFd file(file_fd);

    struct stat status{};
    if(::fstat(file.get(), &status) == -1) {
        throw_system_error(errno, "inspect credential store");
    }
    if(!S_ISREG(status.st_mode) || status.st_nlink != 1) {
        throw std::runtime_error(
            "Credential store must be a regular file with one link"
        );
    }
    if(status.st_uid != ::geteuid()) {
        throw std::runtime_error(
            "Credential store must be owned by the service user"
        );
    }
    if((status.st_mode & 0777) != 0600) {
        throw std::runtime_error(
            "Credential store permissions must be 0600"
        );
    }
    if(
        status.st_size < 0 ||
        static_cast<uintmax_t>(status.st_size) > MAX_STORE_SIZE
    ) {
        throw std::runtime_error("Credential store exceeds the size limit");
    }

    return read_all(file.get(), static_cast<std::size_t>(status.st_size));
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
    if(value.size() > MAX_CREDENTIAL_BLOB_SIZE) {
        throw std::runtime_error(
            std::string(field_name) + " exceeds the size limit"
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

template<typename Container>
class CleanseBuffer {
public:
    explicit CleanseBuffer(Container& value) noexcept : value_(value) {}
    ~CleanseBuffer() {
        OPENSSL_cleanse(value_.data(), value_.size());
    }

    CleanseBuffer(const CleanseBuffer&) = delete;
    CleanseBuffer& operator=(const CleanseBuffer&) = delete;

private:
    Container& value_;
};

} // namespace

CredentialStoreLock::CredentialStoreLock(
    const std::filesystem::path& store_path
) {
    const auto directory_path = prepare_store_directory(store_path);
    auto directory = open_store_directory(directory_path);

    int result;
    do {
        result = ::flock(directory.get(), LOCK_EX | LOCK_NB);
    } while(result == -1 && errno == EINTR);
    if(result == -1) {
        const int error = errno;
        if(error == EWOULDBLOCK || error == EAGAIN) {
            throw std::runtime_error("Credential store is already in use");
        }
        throw_system_error(error, "lock credential store directory");
    }

    directoryFd_ = directory.release();
}

CredentialStoreLock::~CredentialStoreLock() {
    if(directoryFd_ >= 0) {
        (void)::close(directoryFd_);
    }
}

CredentialStore::CredentialStore(
    std::filesystem::path path,
    Key key,
    StoreGenerationCounter* generation_counter
) :
    storePath_(std::move(path)),
    storeKey_(std::move(key)),
    generationCounter_(generation_counter)
{
    if(storeKey_.size() != 32) {
        throw std::invalid_argument("Credential store key must be 32 bytes");
    }
}

CredentialStore::~CredentialStore() {
    OPENSSL_cleanse(storeKey_.data(), storeKey_.size());
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

std::vector<uint8_t> CredentialStore::fromHex(const std::string &s) const {
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
CredentialStore::DecryptedStore CredentialStore::decrypt(
    const std::vector<uint8_t>& ciphertext
) const {
    if(ciphertext.size() < HEADER_SIZE + TAG_SIZE) {
        throw std::runtime_error("Credential store envelope is too short");
    }
    if(!std::equal(STORE_MAGIC.begin(), STORE_MAGIC.end(), ciphertext.begin())) {
        throw std::runtime_error("Credential store has an invalid format marker");
    }
    if(ciphertext[STORE_MAGIC.size()] != STORE_FORMAT_VERSION) {
        throw std::runtime_error("Credential store has an unsupported version");
    }

    const std::size_t generation_offset = STORE_MAGIC.size() + 1;
    const uint64_t generation = read_uint64_be(
        std::span<const uint8_t, GENERATION_SIZE>(
            ciphertext.data() + generation_offset,
            GENERATION_SIZE
        )
    );
    const uint8_t* iv =
        ciphertext.data() + generation_offset + GENERATION_SIZE;
    const uint8_t* cipher = ciphertext.data() + HEADER_SIZE;
    const uint8_t* tag = ciphertext.data() + ciphertext.size() - TAG_SIZE;
    const int ctlen = openssl_checked_size(
        ciphertext.size() - HEADER_SIZE - TAG_SIZE,
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
            context.get(), EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, nullptr
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
            TAG_SIZE,
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
            context.get(),
            nullptr,
            &outl,
            ciphertext.data(),
            openssl_checked_size(HEADER_SIZE, "credential store header")
        ),
        "EVP_DecryptUpdate AAD"
    );
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

    plain.resize(static_cast<std::size_t>(outl + finlen));
    return DecryptedStore{
        .generation = generation,
        .plaintext = std::move(plain)
    };
}

std::vector<uint8_t> CredentialStore::encrypt(
    const std::vector<uint8_t>& plaintext,
    uint64_t generation
) const {
    std::array<uint8_t, NONCE_SIZE> iv{};
    openssl_random_bytes(iv);

    std::vector<uint8_t> out;
    out.reserve(HEADER_SIZE + plaintext.size() + TAG_SIZE);
    out.insert(out.end(), STORE_MAGIC.begin(), STORE_MAGIC.end());
    out.push_back(STORE_FORMAT_VERSION);
    append_uint64_be(out, generation);
    out.insert(out.end(), iv.begin(), iv.end());

    auto context = openssl_make_cipher_context();
    openssl_check(
        EVP_EncryptInit_ex(
            context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr
        ),
        "EVP_EncryptInit_ex"
    );
    openssl_check(
        EVP_CIPHER_CTX_ctrl(
            context.get(), EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, nullptr
        ),
        "EVP_CTRL_GCM_SET_IVLEN"
    );
    openssl_check(
        EVP_EncryptInit_ex(
            context.get(), nullptr, nullptr, storeKey_.data(), iv.data()
        ),
        "EVP_EncryptInit_ex key and IV"
    );

    int outl = 0;
    openssl_check(
        EVP_EncryptUpdate(
            context.get(),
            nullptr,
            &outl,
            out.data(),
            openssl_checked_size(out.size(), "credential store header")
        ),
        "EVP_EncryptUpdate AAD"
    );

    std::vector<uint8_t> cipher(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
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

    std::array<uint8_t, TAG_SIZE> tag{};
    openssl_check(
        EVP_CIPHER_CTX_ctrl(
            context.get(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data()
        ),
        "EVP_CTRL_GCM_GET_TAG"
    );

    out.insert(out.end(), cipher.begin(), cipher.begin() + outl + final_len);
    out.insert(out.end(), tag.begin(), tag.end());
    return out;
}

// Saving credentials to the file
void CredentialStore::save_storage(const Storage& storage) {
    if(requiresReload_) {
        throw std::runtime_error(
            "Credential store must be reloaded after an interrupted commit"
        );
    }

    uint64_t current_generation = generation_;
    if(generationCounter_ != nullptr) {
        current_generation = generationCounter_->read();
        if(current_generation != generation_) {
            throw std::runtime_error(
                "Credential store generation changed unexpectedly"
            );
        }
    }
    if(current_generation == std::numeric_limits<uint64_t>::max()) {
        throw std::overflow_error("Credential store generation overflow");
    }
    const uint64_t next_generation = current_generation + 1;

    using namespace nlohmann;
    json j = json::array();
    for(const auto& item : storage) {
        const auto& cred = item.second;
        j.push_back({
            {"id", toHex(cred.id)},
            {"discoverable", cred.discoverable},
            {"creationOrder", cred.creationOrder},
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
    CleanseBuffer cleanse_plaintext(plaintext);
    std::vector<uint8_t> plain(plaintext.begin(), plaintext.end());
    CleanseBuffer cleanse_plain(plain);
    auto encrypted = encrypt(plain, next_generation);
    atomic_write_file(storePath_, encrypted);

    if(generationCounter_ != nullptr) {
        try {
            generationCounter_->increment();
            if(generationCounter_->read() != next_generation) {
                throw std::runtime_error(
                    "Credential store counter did not advance exactly once"
                );
            }
        } catch(...) {
            requiresReload_ = true;
            throw;
        }
    }
    generation_ = next_generation;
}

CredentialStore::Storage CredentialStore::parse_storage(
    const nlohmann::json& json
) const {
    if(!json.is_array()) throw std::runtime_error("Storage is not an array");
    if(json.size() > MAX_CREDENTIALS) {
        throw std::runtime_error("Credential store contains too many credentials");
    }
    Storage loaded;

    for(const auto &entry : json) {
        if (!entry.is_object()) throw std::runtime_error("Storage entry is not an object");
        StoredCredential cred;
        cred.id = fromHex(entry.at("id").get<std::string>());
        if(cred.id.size() < 16) throw std::runtime_error("Invalid Credential ID");

        const auto& discoverable = entry.at("discoverable");
        if(!discoverable.is_boolean()) {
            throw std::runtime_error("Invalid discoverable credential type");
        }
        cred.discoverable = discoverable.get<bool>();

        const auto& creation_order = entry.at("creationOrder");
        if(!creation_order.is_number_unsigned()) {
            throw std::runtime_error("Invalid credential creation order type");
        }
        cred.creationOrder = creation_order.get<uint64_t>();
        if(cred.creationOrder == 0) {
            throw std::runtime_error("Invalid credential creation order");
        }

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
    const auto encrypted = read_store_file(storePath_);
    if(!encrypted) {
        if(generationCounter_ != nullptr && generationCounter_->read() != 0) {
            throw std::runtime_error(
                "Credential store is missing but its rollback counter is not zero"
            );
        }
        stored_.clear();
        generation_ = 0;
        requiresReload_ = false;
        return;
    }

    auto decrypted = decrypt(*encrypted);
    CleanseBuffer cleanse_plaintext(decrypted.plaintext);
    const uint64_t counter_generation = generationCounter_ == nullptr
        ? decrypted.generation
        : generationCounter_->read();
    if(decrypted.generation < counter_generation) {
        throw std::runtime_error("Credential store rollback detected");
    }
    if(
        decrypted.generation > counter_generation &&
        (
            counter_generation == std::numeric_limits<uint64_t>::max() ||
            decrypted.generation != counter_generation + 1
        )
    ) {
        throw std::runtime_error("Credential store generation is inconsistent");
    }

    json j = json::parse(
        decrypted.plaintext.begin(),
        decrypted.plaintext.end()
    );

    auto loaded = parse_storage(j);

    if(
        generationCounter_ != nullptr &&
        decrypted.generation == counter_generation + 1
    ) {
        generationCounter_->increment();
        if(generationCounter_->read() != decrypted.generation) {
            throw std::runtime_error(
                "Credential store crash recovery counter verification failed"
            );
        }
    }

    stored_.swap(loaded);
    generation_ = decrypted.generation;
    requiresReload_ = false;
}

#ifdef VFIDO_DEVELOPMENT_BUILD
void CredentialStore::clear() {
    Storage empty;
    save_storage(empty);
    stored_.swap(empty);
}
#endif

// Public API

bool CredentialStore::has(const std::vector<uint8_t> &credId) const {
    return stored_.count(toHex(credId)) > 0;
}

bool CredentialStore::has_for_rp(
    const std::vector<uint8_t>& cred_id,
    std::string_view rp_id
) const {
    const auto credential = stored_.find(toHex(cred_id));
    return credential != stored_.end() && credential->second.rpId == rp_id;
}

void CredentialStore::put(const StoredCredential &cred) {
    if(generation_ == std::numeric_limits<uint64_t>::max()) {
        throw std::overflow_error("Credential store generation overflow");
    }

    auto stored_credential = cred;
    stored_credential.creationOrder = generation_ + 1;
    validate_credential(stored_credential);
    const auto credential_id = toHex(stored_credential.id);
    if(stored_.contains(credential_id)) {
        throw std::invalid_argument("Credential ID already exists");
    }

    auto updated = stored_;
    if(stored_credential.discoverable) {
        std::erase_if(updated, [&](const auto& item) {
            const auto& existing = item.second;
            return existing.discoverable &&
                existing.rpId == stored_credential.rpId &&
                existing.userId == stored_credential.userId;
        });
    }
    if(updated.size() >= MAX_CREDENTIALS) {
        throw std::runtime_error("Credential store contains too many credentials");
    }
    updated.emplace(credential_id, std::move(stored_credential));
    save_storage(updated);
    stored_.swap(updated);
}


const StoredCredential& CredentialStore::get_by_credId(const std::vector<uint8_t> &credId) const {
    return stored_.at(toHex(credId));
}

std::vector<StoredCredential> CredentialStore::find_for_assertion(
    std::string_view rp_id,
    std::span<const PublicKeyCredentialDescriptor> allow_list
) const {
    std::vector<StoredCredential> matches;

    if(!allow_list.empty()) {
        std::unordered_set<std::string> seen;
        matches.reserve(allow_list.size());
        for(const auto& descriptor : allow_list) {
            if(descriptor.type != "public-key") {
                continue;
            }

            const auto credential_id = toHex(descriptor.id);
            if(!seen.emplace(credential_id).second) {
                continue;
            }

            const auto credential = stored_.find(credential_id);
            if(
                credential != stored_.end() &&
                credential->second.rpId == rp_id
            ) {
                matches.push_back(credential->second);
            }
        }
        return matches;
    }

    for(const auto& [credential_id, credential] : stored_) {
        (void)credential_id;
        if(credential.discoverable && credential.rpId == rp_id) {
            matches.push_back(credential);
        }
    }
    std::sort(matches.begin(), matches.end(), [](const auto& left, const auto& right) {
        if(left.creationOrder != right.creationOrder) {
            return left.creationOrder > right.creationOrder;
        }
        return left.id < right.id;
    });
    return matches;
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
