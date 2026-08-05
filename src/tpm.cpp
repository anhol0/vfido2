#include "tpm.hpp"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <sys/types.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_esys.h>
#include <stdexcept>
#include <tss2/tss2_tpm2_types.h>
#include <vector>

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

namespace {
    bool nv_index_exists(ESYS_CONTEXT *ctx) {
        ESYS_TR nvHandle = ESYS_TR_NONE;
        TSS2_RC rc = Esys_TR_FromTPMPublic(
                ctx, 
                STORE_KEY_NV_INDEX, 
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 
                &nvHandle
        );
        if(rc != TSS2_RC_SUCCESS) 
            return false;
        
        //Checking if index has actually been written
        TPM2B_NV_PUBLIC *nvPublic = nullptr;
        TPM2B_NAME *nvName = nullptr;
        rc = Esys_NV_ReadPublic(ctx, nvHandle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &nvPublic, &nvName);
        if(rc != TSS2_RC_SUCCESS) {
            Esys_Free(nvPublic);
            Esys_Free(nvName);
            return false;
        }
        bool written = (nvPublic->nvPublic.attributes & TPMA_NV_WRITTEN) != 0;
        Esys_Free(nvPublic);
        Esys_Free(nvName);
        return written;
    }

    void nv_index_undefine(ESYS_CONTEXT *ctx) {
        ESYS_TR nvHandle = ESYS_TR_NONE;
        TSS2_RC rc = Esys_TR_FromTPMPublic(ctx, STORE_KEY_NV_INDEX, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &nvHandle);
        if(rc != TSS2_RC_SUCCESS) {
            return;
        }
        Esys_NV_UndefineSpace(ctx, ESYS_TR_RH_OWNER, nvHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
    }

    void nv_create_and_write_key(ESYS_CONTEXT *ctx, std::vector<uint8_t> &key) {
        // Definition of NV index 
        TPM2B_NV_PUBLIC nvPublic = {};
        nvPublic.size = sizeof(TPMS_NV_PUBLIC);
        nvPublic.nvPublic.nvIndex = STORE_KEY_NV_INDEX;
        nvPublic.nvPublic.nameAlg = TPM2_ALG_SHA256;
        nvPublic.nvPublic.dataSize = STORE_KEY_SIZE;

        //
        nvPublic.nvPublic.attributes = TPMA_NV_OWNERWRITE |
                                       TPMA_NV_OWNERREAD  |
                                       TPMA_NV_NO_DA      |
                                       TPMA_NV_AUTHWRITE  |
                                       TPMA_NV_AUTHREAD;
        TPM2B_AUTH auth = {};
        ESYS_TR nvHandle = ESYS_TR_NONE;
        TSS2_RC rc = Esys_NV_DefineSpace(
                ctx, 
                ESYS_TR_RH_OWNER, 
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, 
                &auth, 
                &nvPublic, 
                &nvHandle
        );
        if(rc != TSS2_RC_SUCCESS) {
            throw std::runtime_error("NV_DefineSpace failed: " + std::string(Tss2_RC_Decode(rc)));
        }

        // Getting a handle to a index 
        rc = Esys_TR_FromTPMPublic(
                ctx, 
                STORE_KEY_NV_INDEX, 
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 
                &nvHandle
        );
        if(rc != TSS2_RC_SUCCESS) {
            throw std::runtime_error("TR_FromTPMPublic failed after define!");
        }
        // Writing key bytes 
        TPM2B_MAX_NV_BUFFER nvData = {};
        nvData.size = STORE_KEY_SIZE;
        memcpy(nvData.buffer, key.data(), STORE_KEY_SIZE);
        rc = Esys_NV_Write(
                ctx, 
                ESYS_TR_RH_OWNER, 
                nvHandle, 
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, 
                &nvData, 
                0
        );
        if(rc != TSS2_RC_SUCCESS) {
            throw std::runtime_error("NV_Write failed: " + std::string(Tss2_RC_Decode(rc)));
        }
    }

    // Read existing NV index  
    static std::vector<uint8_t> nv_read_key(ESYS_CONTEXT *ctx) {
        ESYS_TR nvHandle = {};
        TSS2_RC rc = Esys_TR_FromTPMPublic(
                ctx, STORE_KEY_NV_INDEX, 
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 
                &nvHandle
        );   
        if(rc != TSS2_RC_SUCCESS) {
            throw std::runtime_error("TR_FromTPMPublic failed on read");
        }
        TPM2B_MAX_NV_BUFFER *nvData = nullptr;
        rc = Esys_NV_Read(
                ctx, 
                ESYS_TR_RH_OWNER, 
                nvHandle, 
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, 
                STORE_KEY_SIZE, 
                0, 
                &nvData
        );
        if(rc != TSS2_RC_SUCCESS) {
            throw std::runtime_error("NV_Read failed: " + std::string(Tss2_RC_Decode(rc)));
        }
        std::vector<uint8_t> key(nvData->buffer, nvData->buffer + nvData->size);
        Esys_Free(nvData);
        return key;
    }
}

std::vector<uint8_t> get_or_create_store_key() {
    TpmCtx tpm;

    if(!nv_index_exists(tpm.ctx)) {
        nv_index_undefine(tpm.ctx);
        TPM2B_DIGEST *randBytes = nullptr;
        TSS2_RC rc = Esys_GetRandom(tpm.ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, STORE_KEY_SIZE, &randBytes);
        if(rc != TSS2_RC_SUCCESS) {
            throw std::runtime_error("Esys_GetRandom failed!");
        }
        std::vector<uint8_t> key(randBytes->buffer, randBytes->buffer + randBytes->size);
        Esys_Free(randBytes);
        nv_create_and_write_key(tpm.ctx, key);
        return key;
    }

    return nv_read_key(tpm.ctx);
}
