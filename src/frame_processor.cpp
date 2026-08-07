#include "frame_processor.hpp"

#include <algorithm>
#include <utility>

#include "response.hpp"

namespace {
    constexpr std::size_t HID_FRAME_SIZE = 64;
    constexpr std::size_t UHID_FRAME_SIZE_WITH_REPORT_ID = 65;

    uint32_t frame_cid(std::span<const uint8_t> frame) {
        return
            (static_cast<uint32_t>(frame[0]) << 24) |
            (static_cast<uint32_t>(frame[1]) << 16) |
            (static_cast<uint32_t>(frame[2]) << 8) |
             static_cast<uint32_t>(frame[3]);
    }
}

FrameProcessingResult CTAPHIDFrameProcessor::process(
    std::span<const uint8_t> raw_frame,
    std::optional<uint32_t> active_cid,
    const std::unordered_set<uint32_t>& allocated_cids,
    Clock::time_point now
) {
    std::span<const uint8_t> frame = raw_frame;
    if(
        frame.size() == UHID_FRAME_SIZE_WITH_REPORT_ID &&
        frame[0] == 0
    ) {
        frame = frame.subspan(1);
    }

    if(frame.size() != HID_FRAME_SIZE)
        return std::monostate{};

    const uint32_t cid = frame_cid(frame);
    const bool is_initial = (frame[4] & MASK) != 0;

    if(!is_initial) {
        if(!incoming_ || cid != incoming_->report.cid)
            return std::monostate{};

        UHIDReport& current = incoming_->report;
        const uint8_t sequence = frame[4];

        if(sequence != current.seq) {
            const uint32_t invalid_cid = current.cid;
            incoming_.reset();
            return FrameProcessingError{
                .cid = invalid_cid,
                .error = HIDError::CTAP1_ERR_INVALID_SEQ
            };
        }

        ++current.seq;

        const std::size_t remaining =
            current.len - current.payload.size();
        const std::size_t amount = std::min<std::size_t>(
            remaining,
            MAX_CONT_PAYLOAD_SIZE
        );

        current.payload.insert(
            current.payload.end(),
            frame.begin() + 5,
            frame.begin() + 5 + static_cast<std::ptrdiff_t>(amount)
        );

        if(current.payload.size() != current.len)
            return std::monostate{};

        UHIDReport completed = std::move(current);
        incoming_.reset();
        return completed;
    }

    const uint8_t command = frame[4] & 0x7F;
    const uint16_t length =
        (static_cast<uint16_t>(frame[5]) << 8) |
         static_cast<uint16_t>(frame[6]);

    if(length > max_payload_size) {
        return FrameProcessingError{
            .cid = cid,
            .error = HIDError::CTAP1_ERR_INVALID_LENGTH
        };
    }

    if(
        (command == CTAPHID_INIT && length != 8) ||
        (command == CTAPHID_CANCEL && length != 0)
    ) {
        return FrameProcessingError{
            .cid = cid,
            .error = HIDError::CTAP1_ERR_INVALID_LENGTH
        };
    }

    if(
        command == CTAPHID_CANCEL &&
        (!active_cid || cid != *active_cid)
    ) {
        return std::monostate{};
    }

    if(active_cid) {
        const bool allowed_control_command =
            cid == *active_cid &&
            (command == CTAPHID_CANCEL || command == CTAPHID_INIT);

        if(!allowed_control_command) {
            return FrameProcessingError{
                .cid = cid,
                .error = HIDError::CTAP1_ERR_CHANNEL_BUSY
            };
        }
    }

    if(incoming_ && cid != incoming_->report.cid) {
        return FrameProcessingError{
            .cid = cid,
            .error = HIDError::CTAP1_ERR_CHANNEL_BUSY
        };
    }

    const bool allocating_channel =
        cid == CTAPHID_BROADCAST_CID && command == CTAPHID_INIT;

    if(!allocating_channel && !allocated_cids.contains(cid)) {
        return FrameProcessingError{
            .cid = cid,
            .error = HIDError::CTAP1_ERR_INVALID_CHANNEL
        };
    }

    if(incoming_) {
        if(command == CTAPHID_INIT) {
            incoming_.reset();
        } else {
            const uint32_t interrupted_cid = incoming_->report.cid;
            incoming_.reset();
            return FrameProcessingError{
                .cid = interrupted_cid,
                .error = HIDError::CTAP1_ERR_INVALID_SEQ
            };
        }
    }

    UHIDReport next{};
    next.cid = cid;
    next.cmd = command;
    next.len = length;

    const std::size_t first_payload_size = std::min<std::size_t>(
        length,
        MAX_INIT_PAYLOAD_SIZE
    );

    next.payload.insert(
        next.payload.end(),
        frame.begin() + 7,
        frame.begin() + 7 +
            static_cast<std::ptrdiff_t>(first_payload_size)
    );

    if(next.payload.size() == next.len)
        return next;

    incoming_ = IncomingTransaction{
        .report = std::move(next),
        .deadline = now + message_assembly_timeout
    };
    return std::monostate{};
}

std::optional<FrameProcessingError> CTAPHIDFrameProcessor::expire(
    Clock::time_point now
) {
    if(!incoming_ || now < incoming_->deadline)
        return std::nullopt;

    const uint32_t timed_out_cid = incoming_->report.cid;
    incoming_.reset();
    return FrameProcessingError{
        .cid = timed_out_cid,
        .error = HIDError::CTAP1_ERR_TIMEOUT
    };
}

std::optional<CTAPHIDFrameProcessor::Clock::time_point>
CTAPHIDFrameProcessor::deadline() const noexcept {
    if(!incoming_)
        return std::nullopt;
    return incoming_->deadline;
}

bool CTAPHIDFrameProcessor::has_incoming() const noexcept {
    return incoming_.has_value();
}
