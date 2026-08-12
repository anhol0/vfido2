#include "cbor_utils.hpp"

namespace cbor {
    void check(CborError error, std::string_view operation)
    {
        if(error == CborNoError)
            return;

        throw Error(
            std::string(operation) + ": " +
            cbor_error_string(error)
        );
    }

    std::string read_text(CborValue& value, std::size_t max_length)
    {
        if(!cbor_value_is_text_string(&value))
            throw Error("expected CBOR text string");

        std::size_t length = 0;
        check(
            cbor_value_calculate_string_length(&value, &length),
            "calculate text length"
        );

        if(length > max_length)
            throw Error("CBOR text string exceeds size limit");

        // Extra byte leaves room for TinyCBOR's terminating zero.
        std::vector<char> buffer(length + 1);
        std::size_t copied = length;

        check(
            cbor_value_copy_text_string(
                &value,
                buffer.data(),
                &copied,
                &value
            ),
            "copy text string"
        );

        return std::string(buffer.data(), copied);
    }

    std::vector<uint8_t> read_bytes(CborValue& value, std::size_t max_length)
    {
        if(!cbor_value_is_byte_string(&value))
            throw Error("expected CBOR byte string");

        std::size_t length = 0;
        check(
            cbor_value_calculate_string_length(&value, &length),
            "calculate byte-string length"
        );

        if(length > max_length)
            throw Error("CBOR byte string exceeds size limit");

        std::vector<uint8_t> result(length);
        std::size_t copied = length;

        check(
            cbor_value_copy_byte_string(
                &value,
                result.data(),
                &copied,
                &value
            ),
            "copy byte string"
        );

        result.resize(copied);
        return result;
    }

    uint64_t read_uint(CborValue& value)
    {
        if(!cbor_value_is_unsigned_integer(&value))
            throw Error("expected CBOR unsigned integer");

        uint64_t result = 0;
        check(cbor_value_get_uint64(&value, &result), "read unsigned integer");
        check(cbor_value_advance_fixed(&value), "advance past unsigned integer");
        return result;
    }

    int64_t read_int(CborValue& value)
    {
        if(!cbor_value_is_integer(&value))
            throw Error("expected CBOR integer");

        int64_t result = 0;
        check(cbor_value_get_int64(&value, &result), "read integer");
        check(cbor_value_advance_fixed(&value), "advance past integer");
        return result;
    }

    bool read_bool(CborValue& value)
    {
        if(!cbor_value_is_boolean(&value))
            throw Error("expected CBOR boolean");

        bool result = false;
        check(cbor_value_get_boolean(&value, &result), "read boolean");
        check(cbor_value_advance_fixed(&value), "advance past boolean");
        return result;
    }

    void skip(CborValue& value)
    {
        check(cbor_value_advance(&value), "skip CBOR value");
    }

    void require_complete(
        const CborParser& parser,
        const CborValue& value,
        std::string_view request_name
    ) {
        if(cbor_value_get_next_byte(&value) != parser.source.end) {
            throw Error(
                "trailing data after " + std::string(request_name)
            );
        }
    }
}
