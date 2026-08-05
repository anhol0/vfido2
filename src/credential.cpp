#include "credential.hpp"
#include "tpm.hpp"
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
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include <nlohmann/json.hpp>
#include <vector>

void CredentialStore::init() {
    storeKey_ = get_or_create_store_key(); 
    // std::cout << "storeKey_: ";
    // for (auto byte : storeKey_) {
    //     std::cout << std::format("{:02x}", byte);
    // }
    // std::cout << "\n";
    load();
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

std::vector<uint8_t> CredentialStore::decrypt(std::vector<uint8_t> &ciphertext) {
    if(ciphertext.size() < 28) throw std::runtime_error("Ciphertext is too short");
    const uint8_t *iv = ciphertext.data();
    const uint8_t *tag = ciphertext.data() + 12;
    const uint8_t *cipher = ciphertext.data() + 28;
    int ctlen = ciphertext.size() - 28;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, storeKey_.data(), iv);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag);
    
    std::vector<uint8_t> plain(ctlen);
    int outl = 0;
    EVP_DecryptUpdate(ctx, plain.data(), &outl, cipher, ctlen);
    int finlen = 0;
    if(!EVP_DecryptFinal_ex(ctx, plain.data() + outl, &finlen)) throw std::runtime_error("GCM auth tag mismatch!");
    EVP_CIPHER_CTX_free(ctx);
   
    // if(finlen <= 0) throw std::runtime_error("GCM auth tag mismatch!");
    plain.resize(outl + finlen);
    return plain;
}

std::vector<uint8_t> CredentialStore::encrypt(std::vector<uint8_t> &plaintext) {
    std::vector<uint8_t> iv(12);
    RAND_bytes(iv.data(), iv.size());
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, storeKey_.data(), iv.data());

    std::vector<uint8_t> cipher(plaintext.size());
    int outl = 0;
    EVP_EncryptUpdate(ctx, cipher.data(), &outl, plaintext.data(), plaintext.size());
    int final_len = 0;
    EVP_EncryptFinal_ex(ctx, cipher.data() + outl, &final_len);

    std::vector<uint8_t> tag(16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    EVP_CIPHER_CTX_free(ctx);

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
            std::filesystem::path(CRED_STORE_PATH).parent_path()
    );
    std::ofstream f(CRED_STORE_PATH, std::ios::binary);
    if(!f) throw std::runtime_error("Cannot open file for writing");
    f.write((char*)encrypted.data(), encrypted.size());
}

void CredentialStore::load() {
    using namespace nlohmann;
    stored_.clear();
    if(!std::filesystem::exists(CRED_STORE_PATH)) return;

    std::ifstream f(CRED_STORE_PATH, std::ios::binary);
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


const StoredCredential& CredentialStore::get(const std::vector<uint8_t> &credId) const {
    return stored_.at(toHex(credId)); 
}

void CredentialStore::incrementSigCount(const std::vector<uint8_t> &credId) {
    stored_.at(toHex(credId)).signCount++;
    save();
}
