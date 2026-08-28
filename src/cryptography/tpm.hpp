#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include <tss2/tss2_esys.h>

struct TpmCtx {
    explicit TpmCtx(TSS2_TCTI_CONTEXT* tcti = nullptr);
    ~TpmCtx();

    TpmCtx(const TpmCtx&) = delete;
    TpmCtx& operator=(const TpmCtx&) = delete;

    ESYS_CONTEXT* ctx = nullptr;
};

class TpmTransientHandle {
public:
    explicit TpmTransientHandle(
        ESYS_CONTEXT* context,
        ESYS_TR handle = ESYS_TR_NONE
    ) noexcept : context_(context), handle_(handle) {}

    ~TpmTransientHandle() {
        reset();
    }

    TpmTransientHandle(const TpmTransientHandle&) = delete;
    TpmTransientHandle& operator=(const TpmTransientHandle&) = delete;

    TpmTransientHandle(TpmTransientHandle&& other) noexcept
        : context_(other.context_), handle_(other.release()) {}

    TpmTransientHandle& operator=(TpmTransientHandle&& other) noexcept {
        if(this != &other) {
            reset();
            context_ = other.context_;
            handle_ = other.release();
        }
        return *this;
    }

    [[nodiscard]] ESYS_TR get() const noexcept {
        return handle_;
    }

    [[nodiscard]] ESYS_TR* ptr() noexcept {
        return &handle_;
    }

    void reset(ESYS_TR new_handle = ESYS_TR_NONE) noexcept {
        if(context_ != nullptr && handle_ != ESYS_TR_NONE) {
            (void)Esys_FlushContext(context_, handle_);
        }
        handle_ = new_handle;
    }

    [[nodiscard]] ESYS_TR release() noexcept {
        const ESYS_TR handle = handle_;
        handle_ = ESYS_TR_NONE;
        return handle;
    }

private:
    ESYS_CONTEXT* context_;
    ESYS_TR handle_;
};

struct EsysDeleter {
    void operator()(void* pointer) const noexcept {
        Esys_Free(pointer);
    }
};

template<typename T>
using EsysUniquePtr = std::unique_ptr<T, EsysDeleter>;

struct CredentialKey {
    std::vector<uint8_t> publicBlob;
    std::vector<uint8_t> privateBlob;
};

class CredentialKeyProvider {
public:
    CredentialKeyProvider(
        TSS2_TCTI_CONTEXT* tcti,
        std::span<const uint8_t> master_key
    );
    ~CredentialKeyProvider();

    CredentialKeyProvider(const CredentialKeyProvider&) = delete;
    CredentialKeyProvider& operator=(const CredentialKeyProvider&) = delete;

    [[nodiscard]] CredentialKey create(
        std::span<const uint8_t> credential_id
    );
    [[nodiscard]] std::vector<uint8_t> sign(
        std::span<const uint8_t> credential_id,
        std::span<const uint8_t> digest,
        std::span<const uint8_t> public_blob,
        std::span<const uint8_t> private_blob
    );

private:
    struct Secret {
        ~Secret();
        std::array<uint8_t, 32> bytes{};
    };

    [[nodiscard]] std::array<uint8_t, 32> credential_authorization(
        std::span<const uint8_t> credential_id
    ) const;

    TpmCtx tpm_;
    TpmTransientHandle parent_;
    Secret parentAuthorization_;
    Secret credentialAuthorizationMaster_;
};

[[nodiscard]] std::array<std::vector<uint8_t>, 2> extractPublic(
    std::span<const uint8_t> public_blob
);
