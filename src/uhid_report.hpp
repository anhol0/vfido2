#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

inline constexpr std::size_t CTAPHID_MAX_PAYLOAD_SIZE = 7609;
inline constexpr std::size_t MAX_INIT_PAYLOAD_SIZE = 57; // 64 - 4 - 1 - 2
inline constexpr std::size_t MAX_CONT_PAYLOAD_SIZE = 59; // 64 - 4 - 1

class UHIDReport {
public:
    uint32_t cid;
    uint8_t cmd;
    uint16_t len;
    std::vector<uint8_t> payload;
    uint8_t seq = 0;
    void clear();
};

inline void UHIDReport::clear() {
    payload.clear();
    cid = 0;
    cmd = 0;
    len = 0;
    seq = 0;
}
