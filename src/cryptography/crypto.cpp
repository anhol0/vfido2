#include "crypto.hpp"

#include <limits>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <string>

namespace {

[[noreturn]] void throw_openssl_error(std::string_view operation) {
    const unsigned long error = ERR_get_error();
    if(error == 0) {
        throw std::runtime_error(std::string(operation) + " failed");
    }

    char description[256]{};
    ERR_error_string_n(error, description, sizeof(description));
    throw std::runtime_error(
        std::string(operation) + ": " + description
    );
}

std::vector<uint8_t> sha256_bytes(std::span<const uint8_t> bytes) {
    auto context = openssl_make_digest_context();
    std::vector<uint8_t> hash(EVP_MAX_MD_SIZE);
    unsigned int length = 0;

    openssl_check(
        EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr),
        "EVP_DigestInit_ex"
    );
    openssl_check(
        EVP_DigestUpdate(context.get(), bytes.data(), bytes.size()),
        "EVP_DigestUpdate"
    );
    openssl_check(
        EVP_DigestFinal_ex(context.get(), hash.data(), &length),
        "EVP_DigestFinal_ex"
    );

    hash.resize(length);
    return hash;
}

} // namespace

CipherContext openssl_make_cipher_context() {
    CipherContext context{EVP_CIPHER_CTX_new()};
    if(!context) {
        throw_openssl_error("EVP_CIPHER_CTX_new");
    }
    return context;
}

DigestContext openssl_make_digest_context() {
    DigestContext context{EVP_MD_CTX_new()};
    if(!context) {
        throw_openssl_error("EVP_MD_CTX_new");
    }
    return context;
}

EcdsaSignature openssl_make_ecdsa_signature() {
    EcdsaSignature signature{ECDSA_SIG_new()};
    if(!signature) {
        throw_openssl_error("ECDSA_SIG_new");
    }
    return signature;
}

BigNumber openssl_make_big_number(std::span<const uint8_t> bytes) {
    BigNumber number{
        BN_bin2bn(
            bytes.data(),
            openssl_checked_size(bytes.size(), "BIGNUM input"),
            nullptr
        )
    };
    if(!number) {
        throw_openssl_error("BN_bin2bn");
    }
    return number;
}

void openssl_check(int result, std::string_view operation) {
    if(result == 1) {
        return;
    }

    throw_openssl_error(operation);
}

void openssl_check_positive(int result, std::string_view operation) {
    if(result > 0) {
        return;
    }

    throw_openssl_error(operation);
}

int openssl_checked_size(std::size_t size, std::string_view value_name) {
    if(size > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::length_error(
            std::string(value_name) + " is too large for OpenSSL"
        );
    }
    return static_cast<int>(size);
}

void openssl_random_bytes(std::span<uint8_t> output) {
    openssl_check(
        RAND_bytes(
            output.data(),
            openssl_checked_size(output.size(), "random output")
        ),
        "RAND_bytes"
    );
}

std::vector<uint8_t> sha256(const std::string &str) {
    return sha256_bytes({
        reinterpret_cast<const uint8_t *>(str.data()),
        str.size()
    });
}

std::vector<uint8_t> sha256(const std::vector<uint8_t> &bytes) {
    return sha256_bytes(bytes);
}
