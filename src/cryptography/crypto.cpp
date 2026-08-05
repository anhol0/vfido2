#include "crypto.hpp"
#include <openssl/sha.h>
#include <openssl/evp.h>

std::vector<uint8_t> sha256(std::string &str) {
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    std::vector<uint8_t> hash(EVP_MAX_MD_SIZE);
    uint32_t length = 0;

    EVP_DigestInit_ex(context, EVP_sha256(), nullptr);
    EVP_DigestUpdate(context, str.data(), str.size());
    EVP_DigestFinal_ex(context, hash.data(), &length);
    EVP_MD_CTX_free(context);

    hash.resize(length);
    return hash;
}
