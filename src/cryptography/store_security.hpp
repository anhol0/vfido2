#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include <tss2/tss2_fapi.h>

#include "credentials/credential.hpp"

class FapiStoreSecurity final : public StoreGenerationCounter {
public:
    explicit FapiStoreSecurity(std::string_view authorization);
    ~FapiStoreSecurity() override;

    FapiStoreSecurity(const FapiStoreSecurity&) = delete;
    FapiStoreSecurity& operator=(const FapiStoreSecurity&) = delete;

    void provision();
    [[nodiscard]] std::vector<uint8_t> unseal_key();
    [[nodiscard]] uint64_t read() override;
    void increment() override;

    static constexpr const char* KEY_PATH = "/HS/SRK/vfido-database-key";
    static constexpr const char* COUNTER_PATH =
        "/nv/Owner/vfido-db-generation";

private:
    [[nodiscard]] uint64_t read_raw_counter();

    static TSS2_RC authorize(
        const char* object_path,
        const char* description,
        const char** authorization,
        void* user_data
    );

    FAPI_CONTEXT* context_ = nullptr;
    std::array<char, 33> authorization_{};
    // Integrity-protected inside the same seal as the database key.
    std::optional<uint64_t> counterOrigin_;
};
