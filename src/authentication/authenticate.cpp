#include "authenticate.hpp"
#include <iostream>

bool CTAPGetAssertionRequest::parseRequest(std::vector<uint8_t> &payload) {
    clear();
    uint8_t *buf = payload.data();
    size_t len = payload.size();
    CborParser parser;
    CborValue it;

    CborError err = cbor_parser_init(buf, len, 0, &parser, &it);
    if (err != CborNoError) {
        return false;
    }

    if (!cbor_value_is_map(&it)) {
        std::cerr << "Not a CBOR map!\n";
        return false;
    }

    CborValue map;
    cbor_value_enter_container(&it, &map);

    while (!cbor_value_at_end(&map)) {
        uint64_t key;
        cbor_value_get_uint64(&map, &key);
        cbor_value_advance_fixed(&map);

        if (key < dispatch_table.size() && dispatch_table[key]) {
            if (!(this->*dispatch_table[key])(map))
                return false;
        } else {
            std::cerr << "Unknown key in authenticatorGetAssertion map: " << key << "\n";
            cbor_value_advance(&map);
        }
    }

    cbor_value_leave_container(&it, &map);
    std::cout << "authenticatorGetAssertion parsing successful!\n";
    return true;
}

std::vector<uint8_t> CTAPGetAssertionRequest::build_response(UHIDReport &r)
{
    return std::vector<uint8_t>();
}