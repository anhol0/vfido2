#include "authentication/authenticate.hpp"

#include <array>
#include <cstdint>
#include <iostream>
#include <set>

#include "cbor_operations/cbor_utils.hpp"

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
    } catch(const cbor::Error& error) {
        std::cerr << "Invalid authenticatorGetAssertion request: "
                  << error.what() << '\n';
        clear();
        return false;
    }
}
