#include "credential.hpp"
#include "cryptography/crypto.hpp"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <ios>
#include <iterator>
#include <iostream>
#include <limits>
#include <nlohmann/detail/exceptions.hpp>
#include <nlohmann/detail/value_t.hpp>
#include <nlohmann/json_fwd.hpp>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <nlohmann/json.hpp>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

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
void CredentialStore::save() {
    using namespace nlohmann;
    json j = json::array();
    for (const auto &[hexId, cred] : stored_) {
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
    std::filesystem::create_directories(
            std::filesystem::path(storePath_).parent_path()
    );
    std::ofstream f(storePath_, std::ios::binary);
    if(!f) throw std::runtime_error("Cannot open file for writing");
    f.write((char*)encrypted.data(), encrypted.size());
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
        if(cred.public_blob.empty()) throw std::runtime_error("Empty Public Blob");
        cred.private_blob = read_byte_array(entry, "private_blob");
        if(cred.private_blob.empty()) throw std::runtime_error("Empty Private Blob");

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
    stored_[toHex(cred.id)] = cred;
    save();
}


const StoredCredential& CredentialStore::get_by_credId(const std::vector<uint8_t> &credId) const {
    return stored_.at(toHex(credId));
}

const CredentialStore::Storage CredentialStore::get_all_creds() const
{
    return stored_;
}

void CredentialStore::incrementSigCount(const std::vector<uint8_t> &credId) {
    stored_.at(toHex(credId)).signCount++;
    save();
}
