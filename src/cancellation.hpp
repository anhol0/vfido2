#pragma once

#include <exception>
#include <stop_token>

class OperationCancelled final : public std::exception {
public:
    const char* what() const noexcept override{
        return "CTAP operation cancelled";
    }
};

class UserActionTimedOut final : public std::exception {
public:
    const char* what() const noexcept override {
        return "User action timed out";
    }
};

class UserInteractionCancelled final : public std::exception {
public:
    const char* what() const noexcept override {
        return "User interaction cancelled";
    }
};

inline void cancellation_point(std::stop_token stop) {
    if(stop.stop_requested()) {
        throw OperationCancelled{};
    }
}
