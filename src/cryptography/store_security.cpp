#include "store_security.hpp"

#include <algorithm>
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

uint64_t decode_counter(const uint8_t* data, std::size_t size) {
    if(size != sizeof(uint64_t)) {
        throw std::runtime_error("TPM rollback counter has an invalid size");
    }

    uint64_t value = 0;
    for(std::size_t index = 0; index < size; ++index) {
        value = (value << 8) | data[index];
    }
    if(value == 0) {
        throw std::runtime_error("TPM rollback counter is not initialized");
    }
    return value - 1;
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
    fapi_check(
        Fapi_CreateSeal(
            context_,
            KEY_PATH,
            "system,noda",
            32,
            nullptr,
            authorization_.data(),
            nullptr
        ),
        "Fapi_CreateSeal"
    );

    const TSS2_RC counter_result = Fapi_CreateNv(
        context_,
        COUNTER_PATH,
        "counter,noda",
        sizeof(uint64_t),
        nullptr,
        authorization_.data()
    );
    if(counter_result != TSS2_RC_SUCCESS) {
        const TSS2_RC cleanup_result = Fapi_Delete(context_, KEY_PATH);
        if(cleanup_result != TSS2_RC_SUCCESS) {
            throw std::runtime_error(
                std::string("Fapi_CreateNv failed: ") +
                Tss2_RC_Decode(counter_result) +
                "; cleanup of the newly created seal also failed: " +
                Tss2_RC_Decode(cleanup_result)
            );
        }
        throw_fapi_error(counter_result, "Fapi_CreateNv");
    }

    try {
        fapi_check(
            Fapi_NvIncrement(context_, COUNTER_PATH),
            "initialize rollback counter"
        );
        const auto key = unseal_key();
        if(key.size() != 32 || read() != 0) {
            throw std::runtime_error(
                "Provisioned store security objects are invalid"
            );
        }
    } catch(const std::exception& error) {
        const std::string original_error = error.what();
        const TSS2_RC counter_cleanup = Fapi_Delete(context_, COUNTER_PATH);
        const TSS2_RC key_cleanup = Fapi_Delete(context_, KEY_PATH);
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
    if(size != 32 || data == nullptr) {
        throw std::runtime_error("Sealed database key has an invalid size");
    }
    std::vector<uint8_t> key(data.get(), data.get() + size);
    OPENSSL_cleanse(data.get(), size);
    return key;
}

uint64_t FapiStoreSecurity::read() {
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
    return decode_counter(data.get(), size);
}

void FapiStoreSecurity::increment() {
    fapi_check(
        Fapi_NvIncrement(context_, COUNTER_PATH),
        "Fapi_NvIncrement rollback counter"
    );
}
