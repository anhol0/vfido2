#pragma once

#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <tinycbor/cbor.h>

namespace cbor {
    class Error : public std::runtime_error{
    public:
        using std::runtime_error::runtime_error;
    };

    void check(CborError error, std::string_view operation);
    std::string read_text(CborValue& value, std::size_t max_length);
    std::vector<uint8_t> read_bytes(
          CborValue& value,
          std::size_t max_length
    );
    uint64_t read_uint(CborValue& value);
    int64_t read_int(CborValue& value);
    bool read_bool(CborValue& value);
    void skip(CborValue& value);
    void require_complete(
        const CborParser& parser,
        const CborValue& value,
        std::string_view request_name
    );

    template<typename Function>
    void read_map(CborValue& value, Function&& function)
    {
        if(!cbor_value_is_map(&value))
            throw Error("expected CBOR map");

        CborValue contents;
        check(
            cbor_value_enter_container(&value, &contents),
            "enter map"
        );

        while(!cbor_value_at_end(&contents))
            function(contents);

        check(
            cbor_value_leave_container(&value, &contents),
            "leave map"
        );
    }

    template<typename Function>
    void read_array(CborValue& value, Function&& function)
    {
        if(!cbor_value_is_array(&value))
            throw Error("expected CBOR array");

        CborValue contents;
        check(
            cbor_value_enter_container(&value, &contents),
            "enter array"
        );

        while(!cbor_value_at_end(&contents))
            function(contents);

        check(
            cbor_value_leave_container(&value, &contents),
            "leave array"
        );
    }
}
