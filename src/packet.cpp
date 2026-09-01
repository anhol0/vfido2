#include "response.hpp"

#include "uhid_report.hpp"

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <utility>
#include <vector>

std::vector<std::vector<uint8_t>> CTAPPacket::stringify() {
    if(payload.size() != len)
        throw std::invalid_argument("CTAPHID payload length mismatch");
    if(payload.size() > CTAPHID_MAX_PAYLOAD_SIZE)
        throw std::length_error("CTAPHID payload exceeds transport limit");

    const std::vector<uint8_t> channel_id{
        static_cast<uint8_t>((cid >> 24) & 0xFF),
        static_cast<uint8_t>((cid >> 16) & 0xFF),
        static_cast<uint8_t>((cid >> 8) & 0xFF),
        static_cast<uint8_t>(cid & 0xFF)
    };

    std::vector<std::vector<uint8_t>> frames;
    std::vector<uint8_t> frame;
    frame.reserve(64);
    frame.insert(frame.end(), channel_id.begin(), channel_id.end());
    frame.push_back(cmd);
    frame.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    frame.push_back(static_cast<uint8_t>(len & 0xFF));

    std::size_t payload_offset = 0;
    while(frame.size() < 64) {
        frame.push_back(
            payload_offset < payload.size()
                ? payload[payload_offset++]
                : 0x00
        );
    }
    frames.push_back(std::move(frame));

    uint8_t sequence = 0;
    while(payload_offset < payload.size()) {
        std::vector<uint8_t> continuation;
        continuation.reserve(64);
        continuation.insert(
            continuation.end(),
            channel_id.begin(),
            channel_id.end()
        );
        continuation.push_back(sequence++);
        while(continuation.size() < 64) {
            continuation.push_back(
                payload_offset < payload.size()
                    ? payload[payload_offset++]
                    : 0x00
            );
        }
        frames.push_back(std::move(continuation));
    }
    return frames;
}
