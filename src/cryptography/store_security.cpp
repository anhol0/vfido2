#include "store_security.hpp"

#include <algorithm>
#include <array>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

#include <tss2/tss2_common.h>
#include <tss2/tss2_rc.h>
#include <openssl/crypto.h>

namespace {

struct FapiMemoryDeleter {
    void operator()(void* memory) const noexcept {
        Fapi_Free(memory);
    }
};

template<typename T>
using FapiMemory = std::unique_ptr<T, FapiMemoryDeleter>;

constexpr std::size_t KEY_SIZE = 32;
constexpr std::size_t COUNTER_SIZE = sizeof(uint64_t);
constexpr std::size_t SEALED_MATERIAL_SIZE = KEY_SIZE + COUNTER_SIZE;

struct SealedMaterial {
    ~SealedMaterial() {
        OPENSSL_cleanse(bytes.data(), bytes.size());
    }

    std::array<uint8_t, SEALED_MATERIAL_SIZE> bytes{};
};

[[noreturn]] void throw_fapi_error(TSS2_RC result, const char* operation) {
    throw std::runtime_error(
        std::string(operation) + " failed: " + Tss2_RC_Decode(result)
    );
}

void fapi_check(TSS2_RC result, const char* operation) {
    if(result != TSS2_RC_SUCCESS) {
        throw_fapi_error(result, operation);
    }
}

uint64_t decode_uint64(const uint8_t* data, std::size_t size) {
    if(size != COUNTER_SIZE) {
        throw std::runtime_error("TPM rollback counter has an invalid size");
    }

    uint64_t value = 0;
    for(std::size_t index = 0; index < size; ++index) {
        value = (value << 8) | data[index];
    }
    return value;
}

void encode_uint64(uint64_t value, uint8_t* output) {
    for(std::size_t index = 0; index < COUNTER_SIZE; ++index) {
        const std::size_t shift = (COUNTER_SIZE - index - 1) * 8;
        output[index] = static_cast<uint8_t>(value >> shift);
    }
}

} // namespace

FapiStoreSecurity::FapiStoreSecurity(std::string_view authorization) {
    if(authorization.empty() || authorization.size() > 32) {
        throw std::invalid_argument(
            "Store authorization must contain between 1 and 32 bytes"
        );
    }
    if(authorization.find('\0') != std::string::npos) {
        throw std::invalid_argument("Store authorization must not contain NUL");
    }
    std::copy(
        authorization.begin(),
        authorization.end(),
        authorization_.begin()
    );

    try {
        fapi_check(Fapi_Initialize(&context_, nullptr), "Fapi_Initialize");
        fapi_check(
            Fapi_SetAuthCB(context_, &FapiStoreSecurity::authorize, this),
            "Fapi_SetAuthCB"
        );
    } catch(...) {
        OPENSSL_cleanse(authorization_.data(), authorization_.size());
        if(context_ != nullptr) {
            Fapi_Finalize(&context_);
        }
        throw;
    }
}

FapiStoreSecurity::~FapiStoreSecurity() {
    OPENSSL_cleanse(authorization_.data(), authorization_.size());
    if(context_ != nullptr) {
        Fapi_Finalize(&context_);
    }
}

TSS2_RC FapiStoreSecurity::authorize(
    const char* object_path,
    const char*,
    const char** authorization,
    void* user_data
) {
    if(authorization == nullptr || user_data == nullptr) {
        return TSS2_FAPI_RC_BAD_REFERENCE;
    }

    auto* self = static_cast<FapiStoreSecurity*>(user_data);
    const std::string_view path = object_path == nullptr
        ? std::string_view{}
        : std::string_view{object_path};
    if(
        path.ends_with(KEY_PATH) ||
        path.ends_with(COUNTER_PATH)
    ) {
        *authorization = self->authorization_.data();
    } else {
        *authorization = nullptr;
    }
    return TSS2_RC_SUCCESS;
}

void FapiStoreSecurity::provision() {
    counterOrigin_.reset();
    const TSS2_RC counter_result = Fapi_CreateNv(
        context_,
        COUNTER_PATH,
        "counter,noda",
        sizeof(uint64_t),
        nullptr,
        authorization_.data()
    );
    if(counter_result != TSS2_RC_SUCCESS) {
        throw_fapi_error(counter_result, "Fapi_CreateNv");
    }

    bool key_created = false;
    try {
        fapi_check(
            Fapi_NvIncrement(context_, COUNTER_PATH),
            "initialize rollback counter"
        );
        const uint64_t counter_origin = read_raw_counter();
        if(counter_origin == 0) {
            throw std::runtime_error("TPM rollback counter is not initialized");
        }

        uint8_t* key_raw = nullptr;
        const TSS2_RC random_result = Fapi_GetRandom(
            context_,
            KEY_SIZE,
            &key_raw
        );
        FapiMemory<uint8_t> random_key(key_raw);
        fapi_check(random_result, "Fapi_GetRandom database key");
        if(random_key == nullptr) {
            throw std::runtime_error("Fapi_GetRandom returned no database key");
        }

        SealedMaterial material;
        std::copy_n(random_key.get(), KEY_SIZE, material.bytes.begin());
        OPENSSL_cleanse(random_key.get(), KEY_SIZE);
        encode_uint64(counter_origin, material.bytes.data() + KEY_SIZE);

        fapi_check(
            Fapi_CreateSeal(
                context_,
                KEY_PATH,
                "system,noda",
                material.bytes.size(),
                nullptr,
                authorization_.data(),
                material.bytes.data()
            ),
            "Fapi_CreateSeal"
        );
        key_created = true;

        auto unsealed_key = unseal_key();
        OPENSSL_cleanse(unsealed_key.data(), unsealed_key.size());
        if(read() != 0) {
            throw std::runtime_error(
                "Provisioned store security objects are invalid"
            );
        }
    } catch(const std::exception& error) {
        const std::string original_error = error.what();
        const TSS2_RC counter_cleanup = Fapi_Delete(context_, COUNTER_PATH);
        const TSS2_RC key_cleanup = key_created
            ? Fapi_Delete(context_, KEY_PATH)
            : TSS2_RC_SUCCESS;
        counterOrigin_.reset();
        if(
            counter_cleanup != TSS2_RC_SUCCESS ||
            key_cleanup != TSS2_RC_SUCCESS
        ) {
            throw std::runtime_error(
                original_error + "; cleanup of provisioned objects failed"
            );
        }
        throw;
    }
}

std::vector<uint8_t> FapiStoreSecurity::unseal_key() {
    counterOrigin_.reset();
    std::vector<uint8_t> key(KEY_SIZE);
    uint8_t* data_raw = nullptr;
    std::size_t size = 0;
    const TSS2_RC result = Fapi_Unseal(
        context_,
        KEY_PATH,
        &data_raw,
        &size
    );
    FapiMemory<uint8_t> data(data_raw);
    fapi_check(result, "Fapi_Unseal database key");
    if(size != SEALED_MATERIAL_SIZE || data == nullptr) {
        throw std::runtime_error("Sealed database material has an invalid size");
    }
    const uint64_t counter_origin = decode_uint64(
        data.get() + KEY_SIZE,
        COUNTER_SIZE
    );
    if(counter_origin == 0) {
        OPENSSL_cleanse(data.get(), size);
        throw std::runtime_error("Sealed rollback counter origin is invalid");
    }
    std::copy_n(data.get(), KEY_SIZE, key.begin());
    OPENSSL_cleanse(data.get(), size);
    counterOrigin_ = counter_origin;
    return key;
}

TSS2_TCTI_CONTEXT* FapiStoreSecurity::tcti() {
    TSS2_TCTI_CONTEXT* result = nullptr;
    fapi_check(Fapi_GetTcti(context_, &result), "Fapi_GetTcti");
    if(result == nullptr) {
        throw std::runtime_error("Fapi_GetTcti returned no TPM transport");
    }
    return result;
}

uint64_t FapiStoreSecurity::read_raw_counter() {
    uint8_t* data_raw = nullptr;
    std::size_t size = 0;
    char* log_raw = nullptr;
    const TSS2_RC result = Fapi_NvRead(
        context_,
        COUNTER_PATH,
        &data_raw,
        &size,
        &log_raw
    );
    FapiMemory<uint8_t> data(data_raw);
    FapiMemory<char> log(log_raw);
    fapi_check(result, "Fapi_NvRead rollback counter");
    if(data == nullptr) {
        throw std::runtime_error("TPM rollback counter returned no data");
    }
    const uint64_t value = decode_uint64(data.get(), size);
    if(value == 0) {
        throw std::runtime_error("TPM rollback counter is not initialized");
    }
    return value;
}

uint64_t FapiStoreSecurity::read() {
    if(!counterOrigin_) {
        auto key = unseal_key();
        OPENSSL_cleanse(key.data(), key.size());
    }
    const uint64_t value = read_raw_counter();
    if(value < *counterOrigin_) {
        throw std::runtime_error("TPM rollback counter precedes its sealed origin");
    }
    return value - *counterOrigin_;
}

void FapiStoreSecurity::increment() {
    fapi_check(
        Fapi_NvIncrement(context_, COUNTER_PATH),
        "Fapi_NvIncrement rollback counter"
    );
}
