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
// #include <format>
#include <nlohmann/detail/value_t.hpp>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include <nlohmann/json.hpp>
#include <vector>

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
    for(size_t i = 0; i + 1< s.size(); i += 2) {
        uint8_t b = std::stoul(s.substr(i, 2), nullptr, 16);
        v.push_back(b);
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

void CredentialStore::load() {
    using namespace nlohmann;
    stored_.clear();
    if(!std::filesystem::exists(storePath_)) return;

    std::ifstream f(storePath_, std::ios::binary);
    std::vector<uint8_t> enc_blob(
            (std::istreambuf_iterator<char>(f)),
            std::istreambuf_iterator<char>()
    );
    auto plain = decrypt(enc_blob);
    json j = json::parse(plain.begin(), plain.end());

    for(const auto &entry : j) {
        StoredCredential cred;
        cred.id = fromHex(entry["id"].get<std::string>());
        cred.rpId = entry["rpId"].get<std::string>();
        cred.userId = fromHex(entry["userId"].get<std::string>());
        cred.userName = entry["userName"].get<std::string>();
        cred.userDisplayName = entry["userDisplayName"].get<std::string>();
        cred.alg = entry["alg"].get<int>();
        cred.signCount = entry["signCount"].get<uint32_t>();
        cred.public_blob = entry["public_blob"].get<std::vector<uint8_t>>();
        cred.private_blob = entry["private_blob"].get<std::vector<uint8_t>>();
        stored_[toHex(cred.id)] = cred;
    }
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

const std::unordered_map<std::string, StoredCredential> CredentialStore::get_all_creds() const
{
    return stored_;
}

void CredentialStore::incrementSigCount(const std::vector<uint8_t> &credId) {
    stored_.at(toHex(credId)).signCount++;
    save();
}
