#pragma once

#include <array>
#include <cstdint>
#include <vector>
#include <tss2/tss2_esys.h>
#include <stdexcept>
#include <memory>

static constexpr TPMI_RH_NV_INDEX STORE_KEY_NV_INDEX = 0x01500001;
static constexpr uint16_t         STORE_KEY_SIZE      = 32;

// Abstraction of TPM context
struct TpmCtx {
    ESYS_CONTEXT *ctx = nullptr;
    TpmCtx() {
        TSS2_RC rc = Esys_Initialize(&ctx, nullptr, nullptr);
        if(rc != TSS2_RC_SUCCESS) {
            throw std::runtime_error("Esys initialize error");
        }
    }
    ~TpmCtx() { if(ctx) Esys_Finalize(&ctx); }
};

// Class for Transistent TPM handles got with Esys_Load, Esys_CreateLoaded etc.
class TpmTransistentHandle {
    public:
        TpmTransistentHandle(ESYS_CONTEXT *ctx, ESYS_TR handle = ESYS_TR_NONE)
            : ctx_(ctx), handle_(handle) {}
        ~TpmTransistentHandle() {
            reset();
        }

        // Disable copying
        TpmTransistentHandle(const TpmTransistentHandle&) = delete;
        TpmTransistentHandle& operator=(const TpmTransistentHandle&) = delete;

        // Enable moving
        TpmTransistentHandle(TpmTransistentHandle&& other) noexcept
            : ctx_(other.ctx_), handle_(other.handle_) {
                other.handle_ = ESYS_TR_NONE;
        }
        TpmTransistentHandle& operator=(TpmTransistentHandle&& other) noexcept
        {
            if(this != &other) {
                reset();
                ctx_ = other.ctx_;
                handle_ = other.handle_;
                other.handle_ = ESYS_TR_NONE;
            }
            return *this;
        }

        ESYS_TR get() const { return handle_; }
        ESYS_TR* ptr() { return &handle_; }
        operator ESYS_TR() const { return handle_; }

        // Flushing the handle or replacing it with a new one
        // Freeing memory of the TPM
        void reset(ESYS_TR new_handle = ESYS_TR_NONE) {
            if(ctx_ && handle_ != ESYS_TR_NONE) {
                Esys_FlushContext(ctx_, handle_);
            }
            handle_ = new_handle;
        }

        // Releasing the handle completely
        ESYS_TR release() {
            ESYS_TR temp = handle_;
            handle_ = ESYS_TR_NONE;
            return temp;
        }

    private:
    ESYS_CONTEXT *ctx_;
    ESYS_TR handle_;
};

// Class for Local handles that occupy RAM instead of the TPM memory
// Should be closed with Esys_TR_Close function
class TpmLocalHandle {
    public:
        TpmLocalHandle(ESYS_CONTEXT *ctx, ESYS_TR handle = ESYS_TR_NONE)
            : ctx_(ctx), handle_(handle) {}
        ~TpmLocalHandle() {
            reset();
        }

        // Disable copying
        TpmLocalHandle(const TpmLocalHandle&) = delete;
        TpmLocalHandle& operator=(const TpmLocalHandle&) = delete;

        // Enable moving
        TpmLocalHandle(TpmLocalHandle&& other) noexcept
            : ctx_(other.ctx_), handle_(other.handle_) {
                other.handle_ = ESYS_TR_NONE;
        }
        TpmLocalHandle& operator=(TpmLocalHandle&& other) noexcept
        {
            if(this != &other) {
                reset();
                ctx_ = other.ctx_;
                handle_ = other.handle_;
                other.handle_ = ESYS_TR_NONE;
            }
            return *this;
        }

        ESYS_TR get() const { return handle_; }
        ESYS_TR* ptr() { return &handle_; }
        operator ESYS_TR() const { return handle_; }

        // Flushing the handle or replacing it with a new one
        // Freeing memory of the TPM
        void reset(ESYS_TR new_handle = ESYS_TR_NONE) {
            if(ctx_ && handle_ != ESYS_TR_NONE) {
                Esys_TR_Close(ctx_, &handle_);
            }
            handle_ = new_handle;
        }

    private:
    ESYS_CONTEXT *ctx_;
    ESYS_TR handle_;
};

// Smart TPM Pointer Freeing
struct EsysDeleter {
    void operator()(void* ptr) const {
        if(ptr) {
            Esys_Free(ptr);
        }
    }
};
template <typename T>
using EsysUniquePtr = std::unique_ptr<T, EsysDeleter>;

// Key storage entity
typedef struct CredentialKey {
    std::vector<uint8_t> publicBlob;
    std::vector<uint8_t> privateBlob;
} CredentialKey;

// Getting the persistent handle from the TPM SRK
TpmLocalHandle get_primary(ESYS_CONTEXT *ctx);

// Getting or creating 32 bit encryption key
// Creates the key on the first run and seals it in the TPM NVRAM
// For subsequent runs, it gets it from NVRAM
std::vector<uint8_t> get_or_create_store_key();

// Creating ECC P256 keypair for selected credential
CredentialKey create_credential_key(ESYS_CONTEXT *ctx, ESYS_TR primaryHandle);

// Extracting public key from the blob stored in encrypted JSON file
std::array<std::vector<uint8_t>, 2> extractPublic(std::vector<uint8_t> &pubBlob);

// Signature of the credential for authenticatorGetAssertion method
std::vector<uint8_t> sign(ESYS_CONTEXT *ctx, ESYS_TR primaryHandle, std::vector<uint8_t> &data, std::vector<uint8_t> &publicBlob, std::vector<uint8_t> &privateBlob);
