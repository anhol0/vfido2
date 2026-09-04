#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace vauth::uv {

inline constexpr std::size_t MAX_PASSWORD_SIZE = 1024;

class SensitiveBytes {
public:
    SensitiveBytes() = default;

    explicit SensitiveBytes(std::size_t size) : bytes_(size) {}

    ~SensitiveBytes() {
        clear();
    }

    SensitiveBytes(const SensitiveBytes&) = delete;
    SensitiveBytes& operator=(const SensitiveBytes&) = delete;

    SensitiveBytes(SensitiveBytes&& other) noexcept
        : bytes_(std::move(other.bytes_)) {}

    SensitiveBytes& operator=(SensitiveBytes&& other) noexcept {
        if(this != &other) {
            clear();
            bytes_ = std::move(other.bytes_);
        }
        return *this;
    }

    [[nodiscard]] std::span<const uint8_t> bytes() const noexcept {
        return bytes_;
    }

    [[nodiscard]] std::span<uint8_t> writable_bytes() noexcept {
        return bytes_;
    }

    [[nodiscard]] std::size_t size() const noexcept {
        return bytes_.size();
    }

    void resize(std::size_t size) {
        if(size > bytes_.size())
            throw std::invalid_argument("Sensitive buffer cannot be enlarged");
        if(size < bytes_.size()) {
            explicit_bzero(bytes_.data() + size, bytes_.size() - size);
            bytes_.resize(size);
        }
    }

private:
    void clear() noexcept {
        if(!bytes_.empty())
            explicit_bzero(bytes_.data(), bytes_.size());
    }

    std::vector<uint8_t> bytes_;
};

} // namespace vauth::uv
