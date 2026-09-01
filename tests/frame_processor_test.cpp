#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "frame_processor.hpp"
#include "response.hpp"

namespace {
    constexpr uint32_t CID_A = 0x01020304;
    constexpr uint32_t CID_B = 0x05060708;
    constexpr uint32_t UNKNOWN_CID = 0x11121314;

    void check(bool condition, const char* expression, int line) {
        if(!condition) {
            throw std::runtime_error(
                "CHECK failed at line " + std::to_string(line) +
                ": " + expression
            );
        }
    }

#define CHECK(expression) check((expression), #expression, __LINE__)

    void write_cid(std::span<uint8_t> frame, uint32_t cid) {
        frame[0] = static_cast<uint8_t>((cid >> 24) & 0xFF);
        frame[1] = static_cast<uint8_t>((cid >> 16) & 0xFF);
        frame[2] = static_cast<uint8_t>((cid >> 8) & 0xFF);
        frame[3] = static_cast<uint8_t>(cid & 0xFF);
    }

    std::array<uint8_t, 64> initial_frame(
        uint32_t cid,
        uint8_t command,
        uint16_t declared_length,
        std::span<const uint8_t> payload = {}
    ) {
        if(payload.size() > MAX_INIT_PAYLOAD_SIZE)
            throw std::runtime_error("Initial-frame payload is too large");

        std::array<uint8_t, 64> frame{};
        write_cid(frame, cid);
        frame[4] = command | MASK;
        frame[5] = static_cast<uint8_t>((declared_length >> 8) & 0xFF);
        frame[6] = static_cast<uint8_t>(declared_length & 0xFF);
        std::copy(payload.begin(), payload.end(), frame.begin() + 7);
        return frame;
    }

    std::array<uint8_t, 64> continuation_frame(
        uint32_t cid,
        uint8_t sequence,
        std::span<const uint8_t> payload = {}
    ) {
        if(payload.size() > MAX_CONT_PAYLOAD_SIZE)
            throw std::runtime_error("Continuation payload is too large");

        std::array<uint8_t, 64> frame{};
        write_cid(frame, cid);
        frame[4] = sequence;
        std::copy(payload.begin(), payload.end(), frame.begin() + 5);
        return frame;
    }

    std::array<uint8_t, 65> prefixed_frame(
        const std::array<uint8_t, 64>& frame,
        uint8_t report_id = 0
    ) {
        std::array<uint8_t, 65> prefixed{};
        prefixed[0] = report_id;
        std::copy(frame.begin(), frame.end(), prefixed.begin() + 1);
        return prefixed;
    }

    const UHIDReport& require_report(const FrameProcessingResult& result) {
        const auto* report = std::get_if<UHIDReport>(&result);
        CHECK(report != nullptr);
        return *report;
    }

    const FrameProcessingError& require_error(
        const FrameProcessingResult& result
    ) {
        const auto* error = std::get_if<FrameProcessingError>(&result);
        CHECK(error != nullptr);
        return *error;
    }

    void check_error(
        const FrameProcessingResult& result,
        uint32_t cid,
        HIDError expected
    ) {
        const auto& error = require_error(result);
        CHECK(error.cid == cid);
        CHECK(error.error == expected);
    }

    void test_single_frame_and_report_id() {
        const std::unordered_set<uint32_t> allocated{CID_A};
        const auto now = CTAPHIDFrameProcessor::Clock::time_point{};
        const std::array<uint8_t, 3> payload{0x10, 0x20, 0x30};
        const auto frame = initial_frame(
            CID_A,
            CTAPHID_PING,
            static_cast<uint16_t>(payload.size()),
            payload
        );

        CTAPHIDFrameProcessor processor;
        auto result = processor.process(frame, std::nullopt, allocated, now);
        const auto& report = require_report(result);
        CHECK(report.cid == CID_A);
        CHECK(report.cmd == CTAPHID_PING);
        CHECK(report.len == payload.size());
        CHECK(std::equal(payload.begin(), payload.end(), report.payload.begin()));
        CHECK(!processor.has_incoming());

        CTAPHIDFrameProcessor prefixed_processor;
        const auto prefixed = prefixed_frame(frame);
        result = prefixed_processor.process(
            prefixed,
            std::nullopt,
            allocated,
            now
        );
        CHECK(std::holds_alternative<UHIDReport>(result));

        CTAPHIDFrameProcessor invalid_processor;
        std::array<uint8_t, 63> short_frame{};
        result = invalid_processor.process(
            short_frame,
            std::nullopt,
            allocated,
            now
        );
        CHECK(std::holds_alternative<std::monostate>(result));

        const auto bad_report_id = prefixed_frame(frame, 1);
        result = invalid_processor.process(
            bad_report_id,
            std::nullopt,
            allocated,
            now
        );
        CHECK(std::holds_alternative<std::monostate>(result));
    }

    void test_multipart_reassembly() {
        CTAPHIDFrameProcessor processor;
        const std::unordered_set<uint32_t> allocated{CID_A};
        const auto now = CTAPHIDFrameProcessor::Clock::time_point{};
        const std::array<uint8_t, 57> first_payload = [] {
            std::array<uint8_t, 57> value{};
            value.fill(0xAA);
            return value;
        }();

        auto result = processor.process(
            initial_frame(CID_A, CTAPHID_PING, 58, first_payload),
            std::nullopt,
            allocated,
            now
        );
        CHECK(std::holds_alternative<std::monostate>(result));
        CHECK(processor.has_incoming());

        const std::array<uint8_t, 1> final_payload{0xBB};
        result = processor.process(
            continuation_frame(CID_A, 0, final_payload),
            std::nullopt,
            allocated,
            now
        );

        const auto& report = require_report(result);
        CHECK(report.payload.size() == 58);
        CHECK(report.payload.front() == 0xAA);
        CHECK(report.payload.back() == 0xBB);
        CHECK(!processor.has_incoming());
    }

    void test_partial_message_blocks_other_channel() {
        CTAPHIDFrameProcessor processor;
        const std::unordered_set<uint32_t> allocated{CID_A, CID_B};
        const auto now = CTAPHIDFrameProcessor::Clock::time_point{};
        std::array<uint8_t, 57> first_payload{};

        auto result = processor.process(
            initial_frame(CID_A, CTAPHID_PING, 58, first_payload),
            std::nullopt,
            allocated,
            now
        );
        CHECK(std::holds_alternative<std::monostate>(result));

        const std::array<uint8_t, 1> ping_payload{'B'};
        result = processor.process(
            initial_frame(CID_B, CTAPHID_PING, 1, ping_payload),
            std::nullopt,
            allocated,
            now
        );
        check_error(result, CID_B, HIDError::CTAP1_ERR_CHANNEL_BUSY);
        CHECK(processor.has_incoming());

        const std::array<uint8_t, 1> last_byte{0x42};
        result = processor.process(
            continuation_frame(CID_A, 0, last_byte),
            std::nullopt,
            allocated,
            now
        );
        CHECK(std::holds_alternative<UHIDReport>(result));
    }

    void test_foreign_continuation_is_ignored() {
        CTAPHIDFrameProcessor processor;
        const std::unordered_set<uint32_t> allocated{CID_A, CID_B};
        const auto now = CTAPHIDFrameProcessor::Clock::time_point{};
        std::array<uint8_t, 57> first_payload{};
        const std::array<uint8_t, 1> last_byte{0x55};

        processor.process(
            initial_frame(CID_A, CTAPHID_PING, 58, first_payload),
            std::nullopt,
            allocated,
            now
        );

        auto result = processor.process(
            continuation_frame(CID_B, 0, last_byte),
            std::nullopt,
            allocated,
            now
        );
        CHECK(std::holds_alternative<std::monostate>(result));
        CHECK(processor.has_incoming());

        result = processor.process(
            continuation_frame(CID_A, 0, last_byte),
            std::nullopt,
            allocated,
            now
        );
        CHECK(std::holds_alternative<UHIDReport>(result));
    }

    void test_invalid_sequence_aborts_assembly() {
        CTAPHIDFrameProcessor processor;
        const std::unordered_set<uint32_t> allocated{CID_A, CID_B};
        const auto now = CTAPHIDFrameProcessor::Clock::time_point{};
        std::array<uint8_t, 57> first_payload{};
        const std::array<uint8_t, 1> final_payload{0x01};

        processor.process(
            initial_frame(CID_A, CTAPHID_PING, 58, first_payload),
            std::nullopt,
            allocated,
            now
        );

        auto result = processor.process(
            continuation_frame(CID_A, 1, final_payload),
            std::nullopt,
            allocated,
            now
        );
        check_error(result, CID_A, HIDError::CTAP1_ERR_INVALID_SEQ);
        CHECK(!processor.has_incoming());

        result = processor.process(
            initial_frame(CID_B, CTAPHID_PING, 1, final_payload),
            std::nullopt,
            allocated,
            now
        );
        CHECK(std::holds_alternative<UHIDReport>(result));
    }

    void test_same_cid_init_resynchronizes() {
        CTAPHIDFrameProcessor processor;
        const std::unordered_set<uint32_t> allocated{CID_A};
        const auto now = CTAPHIDFrameProcessor::Clock::time_point{};
        std::array<uint8_t, 57> first_payload{};
        const std::array<uint8_t, 8> nonce{
            0, 1, 2, 3, 4, 5, 6, 7
        };

        processor.process(
            initial_frame(CID_A, CTAPHID_PING, 58, first_payload),
            std::nullopt,
            allocated,
            now
        );

        const auto result = processor.process(
            initial_frame(CID_A, CTAPHID_INIT, 8, nonce),
            std::nullopt,
            allocated,
            now
        );
        const auto& report = require_report(result);
        CHECK(report.cmd == CTAPHID_INIT);
        CHECK(report.payload.size() == nonce.size());
        CHECK(!processor.has_incoming());
    }

    void test_timeout_uses_original_deadline() {
        CTAPHIDFrameProcessor processor;
        const std::unordered_set<uint32_t> allocated{CID_A, CID_B};
        const auto start = CTAPHIDFrameProcessor::Clock::time_point{};
        std::array<uint8_t, 57> first_payload{};
        std::array<uint8_t, 59> continuation_payload{};

        processor.process(
            initial_frame(CID_A, CTAPHID_PING, 117, first_payload),
            std::nullopt,
            allocated,
            start
        );
        CHECK(
            processor.deadline() ==
            start + CTAPHIDFrameProcessor::message_assembly_timeout
        );

        auto result = processor.process(
            continuation_frame(CID_A, 0, continuation_payload),
            std::nullopt,
            allocated,
            start + std::chrono::seconds(2)
        );
        CHECK(std::holds_alternative<std::monostate>(result));
        CHECK(
            processor.deadline() ==
            start + CTAPHIDFrameProcessor::message_assembly_timeout
        );

        CHECK(!processor.expire(start + std::chrono::milliseconds(2999)));
        const auto failure = processor.expire(start + std::chrono::seconds(3));
        CHECK(failure.has_value());
        CHECK(failure->cid == CID_A);
        CHECK(failure->error == HIDError::CTAP1_ERR_TIMEOUT);
        CHECK(!processor.has_incoming());

        const std::array<uint8_t, 1> payload{0x01};
        result = processor.process(
            initial_frame(CID_B, CTAPHID_PING, 1, payload),
            std::nullopt,
            allocated,
            start + std::chrono::seconds(3)
        );
        CHECK(std::holds_alternative<UHIDReport>(result));
    }

    void test_active_request_arbitration() {
        const std::unordered_set<uint32_t> allocated{CID_A, CID_B};
        const auto now = CTAPHIDFrameProcessor::Clock::time_point{};
        const std::array<uint8_t, 1> ping_payload{0x01};
        const std::array<uint8_t, 8> nonce{};
        CTAPHIDFrameProcessor processor;

        auto result = processor.process(
            initial_frame(CID_B, CTAPHID_PING, 1, ping_payload),
            CID_A,
            allocated,
            now
        );
        check_error(result, CID_B, HIDError::CTAP1_ERR_CHANNEL_BUSY);

        result = processor.process(
            initial_frame(CID_A, CTAPHID_PING, 1, ping_payload),
            CID_A,
            allocated,
            now
        );
        check_error(result, CID_A, HIDError::CTAP1_ERR_CHANNEL_BUSY);

        result = processor.process(
            initial_frame(CID_B, CTAPHID_CANCEL, 0),
            CID_A,
            allocated,
            now
        );
        CHECK(std::holds_alternative<std::monostate>(result));

        result = processor.process(
            initial_frame(CID_A, CTAPHID_CANCEL, 0),
            CID_A,
            allocated,
            now
        );
        CHECK(require_report(result).cmd == CTAPHID_CANCEL);

        result = processor.process(
            initial_frame(CID_A, CTAPHID_INIT, 8, nonce),
            CID_A,
            allocated,
            now
        );
        CHECK(require_report(result).cmd == CTAPHID_INIT);

        result = processor.process(
            initial_frame(UNKNOWN_CID, CTAPHID_PING, 1, ping_payload),
            CID_A,
            allocated,
            now
        );
        check_error(result, UNKNOWN_CID, HIDError::CTAP1_ERR_CHANNEL_BUSY);
    }

    void test_lengths_channels_and_broadcast_init() {
        const std::unordered_set<uint32_t> allocated{CID_A};
        const auto now = CTAPHIDFrameProcessor::Clock::time_point{};
        CTAPHIDFrameProcessor processor;

        auto result = processor.process(
            initial_frame(CID_A, CTAPHID_PING, 7610),
            std::nullopt,
            allocated,
            now
        );
        check_error(result, CID_A, HIDError::CTAP1_ERR_INVALID_LENGTH);

        std::array<uint8_t, 7> short_nonce{};
        result = processor.process(
            initial_frame(CID_A, CTAPHID_INIT, 7, short_nonce),
            std::nullopt,
            allocated,
            now
        );
        check_error(result, CID_A, HIDError::CTAP1_ERR_INVALID_LENGTH);

        const std::array<uint8_t, 1> invalid_cancel_payload{0x00};
        result = processor.process(
            initial_frame(
                CID_A,
                CTAPHID_CANCEL,
                1,
                invalid_cancel_payload
            ),
            CID_A,
            allocated,
            now
        );
        check_error(result, CID_A, HIDError::CTAP1_ERR_INVALID_LENGTH);

        const std::array<uint8_t, 1> ping_payload{0x01};
        result = processor.process(
            initial_frame(UNKNOWN_CID, CTAPHID_PING, 1, ping_payload),
            std::nullopt,
            allocated,
            now
        );
        check_error(
            result,
            UNKNOWN_CID,
            HIDError::CTAP1_ERR_INVALID_CHANNEL
        );

        result = processor.process(
            initial_frame(UNKNOWN_CID, CTAPHID_CANCEL, 0),
            std::nullopt,
            allocated,
            now
        );
        CHECK(std::holds_alternative<std::monostate>(result));

        const std::unordered_set<uint32_t> no_allocated_cids;
        const std::array<uint8_t, 8> nonce{};
        result = processor.process(
            initial_frame(CTAPHID_BROADCAST_CID, CTAPHID_INIT, 8, nonce),
            std::nullopt,
            no_allocated_cids,
            now
        );
        const auto& init = require_report(result);
        CHECK(init.cid == CTAPHID_BROADCAST_CID);
        CHECK(init.cmd == CTAPHID_INIT);
    }

    void test_maximum_payload() {
        CTAPHIDFrameProcessor processor;
        const std::unordered_set<uint32_t> allocated{CID_A};
        const auto now = CTAPHIDFrameProcessor::Clock::time_point{};
        std::array<uint8_t, 57> first_payload{};
        std::array<uint8_t, 59> continuation_payload{};

        auto result = processor.process(
            initial_frame(
                CID_A,
                CTAPHID_PING,
                static_cast<uint16_t>(CTAPHIDFrameProcessor::max_payload_size),
                first_payload
            ),
            std::nullopt,
            allocated,
            now
        );
        CHECK(std::holds_alternative<std::monostate>(result));

        for(uint16_t sequence = 0; sequence < 128; ++sequence) {
            result = processor.process(
                continuation_frame(
                    CID_A,
                    static_cast<uint8_t>(sequence),
                    continuation_payload
                ),
                std::nullopt,
                allocated,
                now
            );

            if(sequence < 127)
                CHECK(std::holds_alternative<std::monostate>(result));
        }

        const auto& report = require_report(result);
        CHECK(report.payload.size() == CTAPHIDFrameProcessor::max_payload_size);
        CHECK(!processor.has_incoming());
    }

    void test_outgoing_payload_bounds_and_lengths() {
        CTAPPacket maximum{
            .cid = CID_A,
            .cmd = static_cast<uint8_t>(CTAPHID_CBOR | MASK),
            .len = static_cast<uint16_t>(CTAPHID_MAX_PAYLOAD_SIZE),
            .payload = std::vector<uint8_t>(
                CTAPHID_MAX_PAYLOAD_SIZE,
                0xA5
            )
        };
        const auto frames = maximum.stringify();
        CHECK(frames.size() == 129);
        CHECK(std::all_of(frames.begin(), frames.end(), [](const auto& frame) {
            return frame.size() == 64;
        }));
        CHECK(frames.front()[4] == (CTAPHID_CBOR | MASK));
        CHECK(frames.back()[4] == 127);

        CTAPPacket mismatched{
            .cid = CID_A,
            .cmd = static_cast<uint8_t>(CTAPHID_CBOR | MASK),
            .len = 2,
            .payload = {0x00}
        };
        bool mismatch_rejected = false;
        try {
            static_cast<void>(mismatched.stringify());
        } catch(const std::invalid_argument&) {
            mismatch_rejected = true;
        }
        CHECK(mismatch_rejected);

        CTAPPacket oversized{
            .cid = CID_A,
            .cmd = static_cast<uint8_t>(CTAPHID_CBOR | MASK),
            .len = static_cast<uint16_t>(CTAPHID_MAX_PAYLOAD_SIZE + 1),
            .payload = std::vector<uint8_t>(
                CTAPHID_MAX_PAYLOAD_SIZE + 1,
                0xA5
            )
        };
        bool oversized_rejected = false;
        try {
            static_cast<void>(oversized.stringify());
        } catch(const std::length_error&) {
            oversized_rejected = true;
        }
        CHECK(oversized_rejected);
    }

    using Test = std::pair<const char*, std::function<void()>>;
}

int main() {
    const std::vector<Test> tests{
        {"single frame and report ID", test_single_frame_and_report_id},
        {"multipart reassembly", test_multipart_reassembly},
        {"partial message blocks another channel", test_partial_message_blocks_other_channel},
        {"foreign continuation is ignored", test_foreign_continuation_is_ignored},
        {"invalid sequence aborts assembly", test_invalid_sequence_aborts_assembly},
        {"same-CID INIT resynchronizes", test_same_cid_init_resynchronizes},
        {"timeout uses original deadline", test_timeout_uses_original_deadline},
        {"active request arbitration", test_active_request_arbitration},
        {"lengths, channels, and broadcast INIT", test_lengths_channels_and_broadcast_init},
        {"maximum payload", test_maximum_payload},
        {"outgoing payload bounds and lengths", test_outgoing_payload_bounds_and_lengths}
    };

    std::size_t failed = 0;
    for(const auto& [name, test] : tests) {
        try {
            test();
            std::cout << "PASS: " << name << '\n';
        } catch(const std::exception& error) {
            ++failed;
            std::cerr << "FAIL: " << name << ": " << error.what() << '\n';
        }
    }

    if(failed != 0) {
        std::cerr << failed << " test(s) failed\n";
        return 1;
    }

    std::cout << tests.size() << " test(s) passed\n";
    return 0;
}
