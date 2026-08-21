#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <span>
#include <string>
#include <string_view>
#include <vector>

struct CipherContextDeleter {
    void operator()(EVP_CIPHER_CTX* context) const noexcept {
        EVP_CIPHER_CTX_free(context);
    }
};

using CipherContext =
    std::unique_ptr<EVP_CIPHER_CTX, CipherContextDeleter>;

struct DigestContextDeleter {
    void operator()(EVP_MD_CTX* context) const noexcept {
        EVP_MD_CTX_free(context);
    }
};

using DigestContext =
    std::unique_ptr<EVP_MD_CTX, DigestContextDeleter>;

struct EcdsaSignatureDeleter {
    void operator()(ECDSA_SIG* signature) const noexcept {
        ECDSA_SIG_free(signature);
    }
};

using EcdsaSignature =
    std::unique_ptr<ECDSA_SIG, EcdsaSignatureDeleter>;

struct BigNumberDeleter {
    void operator()(BIGNUM* number) const noexcept {
        BN_free(number);
    }
};

using BigNumber =
    std::unique_ptr<BIGNUM, BigNumberDeleter>;

CipherContext openssl_make_cipher_context();
DigestContext openssl_make_digest_context();
EcdsaSignature openssl_make_ecdsa_signature();
BigNumber openssl_make_big_number(std::span<const uint8_t> bytes);

void openssl_check(int result, std::string_view operation);
void openssl_check_positive(int result, std::string_view operation);
int openssl_checked_size(std::size_t size, std::string_view value_name);
void openssl_random_bytes(std::span<uint8_t> output);

struct Credential {
    std::vector<uint8_t> id;
    int32_t alg;
    std::vector<uint8_t> private_key;
};

std::vector<uint8_t> sha256(const std::string &str);
std::vector<uint8_t> sha256(const std::vector<uint8_t> &bytes);
