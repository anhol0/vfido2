#pragma once

#include <array>
#include <cstdint>
#include <vector>
#include <tss2/tss2_esys.h>
#include <stdexcept>

static constexpr TPMI_RH_NV_INDEX STORE_KEY_NV_INDEX = 0x01500001;
static constexpr uint16_t         STORE_KEY_SIZE      = 32;

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

typedef struct CredentialKey {
    std::vector<uint8_t> publicBlob;
    std::vector<uint8_t> privateBlob;
} CredentialKey; 

// Returns 32 bit encryption key.
// On the first run generates it using TPM 
// On subsequent runs gets it from the TPM NVRAM
ESYS_TR create_primary(ESYS_CONTEXT *ctx);
std::vector<uint8_t> get_or_create_store_key();
CredentialKey create_credential_key(ESYS_CONTEXT *ctx, ESYS_TR primaryHandle);
std::array<std::vector<uint8_t>, 2> extract(std::vector<uint8_t> &pubBlob);


