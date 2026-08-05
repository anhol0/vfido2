#pragma once

#include <variant>
#include <string>
#include <vector>
#include <cstdint>

enum class Type {
        Bool,
        Int,
        String,
        Bytes,
        Map,
        Array,
        Unknown
};

typedef struct ExtensionValue {
    Type type;
    std::variant<bool, int64_t, std::string, std::vector<uint8_t>> value;
} ExtensionValue;