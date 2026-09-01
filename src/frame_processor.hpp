#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <unordered_set>
#include <variant>

#include "error.hpp"
#include "uhid_report.hpp"

inline constexpr uint32_t CTAPHID_INVALID_CID = 0x00000000;
inline constexpr uint32_t CTAPHID_BROADCAST_CID = 0xFFFFFFFF;

struct FrameProcessingError {
    uint32_t cid;
    HIDError error;
};

using FrameProcessingResult = std::variant<
    std::monostate,
    UHIDReport,
    FrameProcessingError
>;

class CTAPHIDFrameProcessor {
public:
    using Clock = std::chrono::steady_clock;

    static constexpr std::size_t max_payload_size =
        CTAPHID_MAX_PAYLOAD_SIZE;
    static constexpr auto message_assembly_timeout =
        std::chrono::seconds(3);

    FrameProcessingResult process(
        std::span<const uint8_t> raw_frame,
        std::optional<uint32_t> active_cid,
        const std::unordered_set<uint32_t>& allocated_cids,
        Clock::time_point now
    );

    std::optional<FrameProcessingError> expire(Clock::time_point now);
    std::optional<Clock::time_point> deadline() const noexcept;
    bool has_incoming() const noexcept;

private:
    struct IncomingTransaction {
        UHIDReport report;
        Clock::time_point deadline;
    };

    std::optional<IncomingTransaction> incoming_;
};
