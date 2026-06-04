#include "tpm.hpp"
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <nlohmann/detail/value_t.hpp>
#include <string>
#include <sys/types.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_esys.h>
#include <stdexcept>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_mu.h>
#include <vector>

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
        // nvPublic.size = sizeof(TPMS_NV_PUBLIC);
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

ESYS_TR create_primary(ESYS_CONTEXT *ctx) {
    TPM2B_PUBLIC tmpl = {};
    auto &t = tmpl.publicArea;
    t.type = TPM2_ALG_ECC;
    t.nameAlg = TPM2_ALG_SHA256;
    t.objectAttributes = TPMA_OBJECT_RESTRICTED          |
                         TPMA_OBJECT_DECRYPT             |  // storage/parent key = DECRYPT
                         TPMA_OBJECT_FIXEDTPM            |
                         TPMA_OBJECT_FIXEDPARENT         |
                         TPMA_OBJECT_SENSITIVEDATAORIGIN |
                         TPMA_OBJECT_USERWITHAUTH;
    t.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_AES;
    t.parameters.eccDetail.symmetric.keyBits.aes = 128;
    t.parameters.eccDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    t.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
    t.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
    t.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
    
    TPM2B_SENSITIVE_CREATE sens = {};
    TPM2B_DATA outsideInfo = {};
    TPML_PCR_SELECTION pcrsel = {};
    ESYS_TR handle = {};
    TPM2B_PUBLIC *outPub = nullptr;
    TSS2_RC rc = Esys_CreatePrimary(
            ctx, 
            ESYS_TR_RH_OWNER, 
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, 
            &sens, &tmpl, 
            &outsideInfo, &pcrsel, 
            &handle, 
            &outPub, 
            nullptr, nullptr, nullptr
    );

    Esys_Free(outPub);

    if(rc != TSS2_RC_SUCCESS) {
        throw std::runtime_error("CreatePrimary failed: " + std::string(Tss2_RC_Decode(rc)));
    }

    return handle; // Caller must do Esys_FlushContext when done
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

CredentialKey create_credential_key(ESYS_CONTEXT *ctx, ESYS_TR primaryHandle) {
    TPM2B_TEMPLATE tmplBuffer = {};
    TPMT_PUBLIC tmpt = {};
    tmpt.type = TPM2_ALG_ECC;
    tmpt.nameAlg = TPM2_ALG_SHA256;
    tmpt.objectAttributes = TPMA_OBJECT_SIGN_ENCRYPT        |
                            TPMA_OBJECT_FIXEDTPM            |
                            TPMA_OBJECT_FIXEDPARENT         |
                            TPMA_OBJECT_SENSITIVEDATAORIGIN |
                            TPMA_OBJECT_USERWITHAUTH;
    tmpt.authPolicy.size = 0;
    tmpt.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
    tmpt.parameters.eccDetail.scheme.scheme = TPM2_ALG_ECDSA;
    tmpt.parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
    tmpt.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
    tmpt.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
    tmpt.unique.ecc.x.size = 0;
    tmpt.unique.ecc.y.size = 0; 

    size_t offset = 0;
    Tss2_MU_TPMT_PUBLIC_Marshal(&tmpt, tmplBuffer.buffer, sizeof(tmplBuffer.buffer), &offset);
    tmplBuffer.size = (uint16_t)offset;
    ESYS_TR keyHandle = ESYS_TR_NONE;
    TPM2B_PUBLIC *outPublic = nullptr;
    TPM2B_PRIVATE *outPrivate = nullptr; 

    TPM2B_SENSITIVE_CREATE sens = {};
    TSS2_RC rc = Esys_CreateLoaded(
            ctx, 
            primaryHandle, 
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, 
            &sens, 
            &tmplBuffer, 
            &keyHandle, 
            &outPrivate, 
            &outPublic      
    );

    if(rc != TSS2_RC_SUCCESS) {
        Esys_Free(outPublic);
        Esys_Free(outPrivate);
        throw std::runtime_error("CreateLoaded failed: " + std::string(Tss2_RC_Decode(rc)));
    }


    CredentialKey result;
    auto pub_size = sizeof(outPublic->size) + outPublic->size; 
    auto priv_size = sizeof(outPrivate->size) + outPrivate->size; 
    std::vector<uint8_t> public_blob(pub_size);
    std::vector<uint8_t> private_blob(priv_size);
    
    // Serializing public area
    offset = 0;
    rc = Tss2_MU_TPM2B_PUBLIC_Marshal(outPublic, public_blob.data(), public_blob.size(), &offset);
    if(rc != TSS2_RC_SUCCESS) {
        Esys_Free(outPublic);
        Esys_Free(outPrivate);
        throw std::runtime_error("Failed to serialize public data: " + std::string(Tss2_RC_Decode(rc)));
    }

    // Serializing private area
    offset = 0;
    rc = Tss2_MU_TPM2B_PRIVATE_Marshal(outPrivate, private_blob.data(), private_blob.size(), &offset);
    if(rc != TSS2_RC_SUCCESS) {
        Esys_Free(outPublic);
        Esys_Free(outPrivate);
        throw std::runtime_error("Failed to serialize private data: " + std::string(Tss2_RC_Decode(rc)));
    }    
    
    Esys_Free(outPrivate);
    Esys_Free(outPublic);
    Esys_FlushContext(ctx, keyHandle);
    result.publicBlob = public_blob;
    result.privateBlob = private_blob;
    return  result;
}

std::array<std::vector<uint8_t>, 2> extract(std::vector<uint8_t> &pubBlob) {
    TPM2B_PUBLIC tpm2Public = {};
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(pubBlob.data(), pubBlob.size(), &offset, &tpm2Public);
    if(rc != TSS2_RC_SUCCESS) {
        throw std::runtime_error("Failed to unserialize public data: " + std::string(Tss2_RC_Decode(rc)));
    }

    const TPMT_PUBLIC &publicKey = tpm2Public.publicArea;
    if (publicKey.type != TPM2_ALG_ECC) {
        throw std::runtime_error("The provided key blob is not an ECC key.");
    }

    return std::array<std::vector<uint8_t>, 2> {
        std::vector<uint8_t>(publicKey.unique.ecc.x.buffer, publicKey.unique.ecc.x.buffer+publicKey.unique.ecc.x.size), 
        std::vector<uint8_t>(publicKey.unique.ecc.y.buffer, publicKey.unique.ecc.y.buffer+publicKey.unique.ecc.y.size)
    };
}
