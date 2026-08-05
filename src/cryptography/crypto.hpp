#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <cstdint>
#include <string>
#include <vector>

struct Credential {
    std::vector<uint8_t> id;
    int32_t alg;
    std::vector<uint8_t> private_key;
};

std::vector<uint8_t> sha256(std::string &str);
std::vector<uint8_t> sha256(std::vector<uint8_t> &bytes);

#endif
