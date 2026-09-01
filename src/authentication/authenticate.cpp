#include "authentication/authenticate.hpp"

#include <array>
#include <cstdint>
#include <set>
#include <utility>

#include "cbor_operations/cbor_utils.hpp"

void AssertionSequence::begin(
    uint32_t origin_cid,
    std::vector<StoredCredential> remaining_credentials,
    Clock::time_point now
) {
    clear();
    if(origin_cid == 0 || remaining_credentials.empty()) {
        return;
    }

    originCid_ = origin_cid;
    credentials_ = std::move(remaining_credentials);
    lastUse_ = now;
}

std::optional<StoredCredential> AssertionSequence::next(
    uint32_t cid,
    Clock::time_point now
) {
    if(originCid_ == 0 || cid != originCid_) {
        return std::nullopt;
    }
    if(now - lastUse_ > TIMEOUT || index_ >= credentials_.size()) {
        clear();
        return std::nullopt;
    }

    auto credential = credentials_[index_++];
    if(index_ == credentials_.size()) {
        clear();
    } else {
        lastUse_ = now;
    }
    return credential;
}

void AssertionSequence::clear() noexcept {
    credentials_.clear();
    index_ = 0;
    originCid_ = 0;
    lastUse_ = {};
}

uint32_t AssertionSequence::origin_cid() const noexcept {
    return originCid_;
}

bool CTAPGetAssertionRequest::parseRequest(
    std::vector<uint8_t>& payload
) {
    clear();

    try {
        CborParser parser;
        CborValue root;
        cbor::check(
            cbor_parser_init(
                payload.data(),
                payload.size(),
                0,
                &parser,
                &root
            ),
            "initialize GetAssertion parser"
        );

        std::set<uint64_t> seen;
        cbor::read_map(root, [&](CborValue& map) {
            const uint64_t key = cbor::read_uint(map);

            if(!seen.insert(key).second)
                throw cbor::Error("duplicate GetAssertion parameter");

            if(key < dispatch_table.size() && dispatch_table[key]) {
                (this->*dispatch_table[key])(map);
            } else {
                cbor::skip(map);
            }
        });

        constexpr std::array<uint64_t, 2> required{1, 2};
        for(const uint64_t key : required) {
            if(!seen.contains(key))
                throw cbor::Error("missing required GetAssertion parameter");
        }

        cbor::require_complete(parser, root, "GetAssertion request");

        return true;
    } catch(const cbor::Error&) {
        clear();
        return false;
    }
}
