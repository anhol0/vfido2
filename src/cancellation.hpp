#pragma once

#include <exception>
#include <stop_token>

class OperationCancelled final : public std::exception {
public:
    const char* what() const noexcept override{
        return "CTAP operation cancelled";
    }
};

inline void cancellation_point(std::stop_token stop) {
    if(stop.stop_requested()) {
        throw OperationCancelled{};
    }
}
