#include "tpm.hpp"
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <nlohmann/detail/value_t.hpp>
#include <openssl/bn.h>
#include <openssl/ec.h>
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
        TpmLocalHandle nvHandle(ctx);
        TSS2_RC rc = Esys_TR_FromTPMPublic(
                ctx,
                STORE_KEY_NV_INDEX,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                nvHandle.ptr()
        );
        if(rc != TSS2_RC_SUCCESS)
            return false;

        //Checking if index has actually been written

        TPM2B_NV_PUBLIC *nvPublicRaw = nullptr;
        TPM2B_NAME *nvNameRaw = nullptr;
        rc = Esys_NV_ReadPublic(ctx, nvHandle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &nvPublicRaw, &nvNameRaw);
        if(rc != TSS2_RC_SUCCESS) {
            return false;
        }
        EsysUniquePtr<TPM2B_NV_PUBLIC> nvPublic(nvPublicRaw);
        EsysUniquePtr<TPM2B_NAME> nvName(nvNameRaw);
        bool written = (nvPublic->nvPublic.attributes & TPMA_NV_WRITTEN) != 0;
        return written;
    }

    void nv_index_undefine(ESYS_CONTEXT *ctx) {
        ESYS_TR nvHandle = ESYS_TR_NONE;
        TSS2_RC rc = Esys_TR_FromTPMPublic(ctx, STORE_KEY_NV_INDEX, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &nvHandle);
        if(rc != TSS2_RC_SUCCESS) {
            return;
        }
        TpmLocalHandle nvGuard(ctx, nvHandle);
        Esys_NV_UndefineSpace(ctx, ESYS_TR_RH_OWNER, nvHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
        // nvGuard will take care about freeing memory allocated for the handle
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

        TpmLocalHandle nvHandleGuard(ctx, nvHandle);

        // Writing key bytes
        TPM2B_MAX_NV_BUFFER nvData = {};
        nvData.size = STORE_KEY_SIZE;
        memcpy(nvData.buffer, key.data(), STORE_KEY_SIZE);
        rc = Esys_NV_Write(
                ctx,
                ESYS_TR_RH_OWNER,
                nvHandleGuard,
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                &nvData,
                0
        );
        if(rc != TSS2_RC_SUCCESS) {
            throw std::runtime_error("NV_Write failed: " + std::string(Tss2_RC_Decode(rc)));
        }
        // Deallocation of nvHandle will be taken care of by nvHandleGuard
    }

    // Read existing NV index
    static std::vector<uint8_t> nv_read_key(ESYS_CONTEXT *ctx) {
        ESYS_TR nvHandle = {};
        TSS2_RC rc = Esys_TR_FromTPMPublic(
                ctx, STORE_KEY_NV_INDEX,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                &nvHandle
        );
        if(rc != TSS2_RC_SUCCESS) throw std::runtime_error("TR_FromTPMPublic failed on read");
        TpmLocalHandle nvHandleGuard(ctx, nvHandle);

        TPM2B_MAX_NV_BUFFER *nvDataRaw = nullptr;
        rc = Esys_NV_Read(
                ctx,
                ESYS_TR_RH_OWNER,
                nvHandleGuard.get(),
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                STORE_KEY_SIZE,
                0,
                &nvDataRaw
        );
        if(rc != TSS2_RC_SUCCESS) {
            throw std::runtime_error("NV_Read failed: " + std::string(Tss2_RC_Decode(rc)));
        }
        EsysUniquePtr<TPM2B_MAX_NV_BUFFER> nvData(nvDataRaw);
        std::vector<uint8_t> key(nvData->buffer, nvData->buffer + nvData->size);
        return key;
    }
}

TpmLocalHandle get_primary(ESYS_CONTEXT *ctx) {
    ESYS_TR primaryHandle = ESYS_TR_NONE;
    TSS2_RC rc = Esys_TR_FromTPMPublic(
        ctx,
        0x81000001, // Well-known persistent SRK handle
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        &primaryHandle
    );
    if (rc != TSS2_RC_SUCCESS) {
        throw std::runtime_error("Failed to load persistent SRK handle: " + std::string(Tss2_RC_Decode(rc)));
    }
    return TpmLocalHandle(ctx, primaryHandle);
}

std::vector<uint8_t> get_or_create_store_key() {
    TpmCtx tpm;

    if(!nv_index_exists(tpm.ctx)) {
        nv_index_undefine(tpm.ctx);
        TPM2B_DIGEST *randBytesRaw = nullptr;
        TSS2_RC rc = Esys_GetRandom(tpm.ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, STORE_KEY_SIZE, &randBytesRaw);
        if(rc != TSS2_RC_SUCCESS) {
            throw std::runtime_error("Esys_GetRandom failed!");
        }
        EsysUniquePtr<TPM2B_DIGEST> randBytes(randBytesRaw);
        std::vector<uint8_t> key(randBytes->buffer, randBytes->buffer + randBytes->size);
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
    TpmTransistentHandle keyHandle(ctx);
    TPM2B_PUBLIC *outPublicRaw = nullptr;
    TPM2B_PRIVATE *outPrivateRaw = nullptr;

    TPM2B_SENSITIVE_CREATE sens = {};
    TSS2_RC rc = Esys_CreateLoaded(
            ctx,
            primaryHandle,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &sens,
            &tmplBuffer,
            keyHandle.ptr(),
            &outPrivateRaw,
            &outPublicRaw
    );

    if(rc != TSS2_RC_SUCCESS) {
        throw std::runtime_error("CreateLoaded failed: " + std::string(Tss2_RC_Decode(rc)));
    }

    EsysUniquePtr<TPM2B_PUBLIC> outPublic(outPublicRaw);
    EsysUniquePtr<TPM2B_PRIVATE> outPrivate(outPrivateRaw);


    CredentialKey result;
    auto pub_size = sizeof(outPublic->size) + outPublic->size;
    auto priv_size = sizeof(outPrivate->size) + outPrivate->size;
    std::vector<uint8_t> public_blob(pub_size);
    std::vector<uint8_t> private_blob(priv_size);

    // Serializing public area
    offset = 0;
    rc = Tss2_MU_TPM2B_PUBLIC_Marshal(outPublic.get(), public_blob.data(), public_blob.size(), &offset);
    if(rc != TSS2_RC_SUCCESS) {
        throw std::runtime_error("Failed to serialize public data: " + std::string(Tss2_RC_Decode(rc)));
    }

    // Serializing private area
    offset = 0;
    rc = Tss2_MU_TPM2B_PRIVATE_Marshal(outPrivate.get(), private_blob.data(), private_blob.size(), &offset);
    if(rc != TSS2_RC_SUCCESS) {
        throw std::runtime_error("Failed to serialize private data: " + std::string(Tss2_RC_Decode(rc)));
    }

    result.publicBlob = public_blob;
    result.privateBlob = private_blob;
    return  result;
}

std::array<std::vector<uint8_t>, 2> extractPublic(std::vector<uint8_t> &pubBlob) {
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

std::vector<uint8_t> sign
(
    ESYS_CONTEXT *ctx,
    ESYS_TR primaryHandle,
    std::vector<uint8_t> &data,
    std::vector<uint8_t> &publicBlob,
    std::vector<uint8_t> &privateBlob
) {
    TPM2B_DIGEST digest = {};
    digest.size = data.size();
    std::copy(data.begin(), data.end(), digest.buffer);

    TPMT_SIG_SCHEME inScheme = {
        .scheme = TPM2_ALG_ECDSA,
        .details = {.ecdsa = {.hashAlg = TPM2_ALG_SHA256}}
    };

    // Unmarshal the private blob
    TPM2B_PRIVATE inPrivate = {};
    size_t offset = 0;
    Tss2_MU_TPM2B_PRIVATE_Unmarshal(privateBlob.data(), privateBlob.size(), &offset, &inPrivate);

    // Unmarshal the public blob
    TPM2B_PUBLIC inPublic = {};
    offset = 0;
    Tss2_MU_TPM2B_PUBLIC_Unmarshal(publicBlob.data(), publicBlob.size(), &offset, &inPublic);

    // Generating the key handle
    // ESYS_TR keyHandle = ESYS_TR_NONE;
    TpmTransistentHandle keyHandle(ctx);
    TSS2_RC rc = Esys_Load(
        ctx,
        primaryHandle,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        &inPrivate,
        &inPublic,
        keyHandle.ptr()
    );
    if (rc != TSS2_RC_SUCCESS) {
        throw std::runtime_error("Esys_Load failed: " + std::string(Tss2_RC_Decode(rc)));
    }

    TPMT_TK_HASHCHECK validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_NULL,
        .digest = {0}
    };
    TPMT_SIGNATURE *signatureRaw = nullptr;
    rc = Esys_Sign(
        ctx,
        keyHandle,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        &digest,
        &inScheme,
        &validation,
        &signatureRaw
    );
    if (rc != TSS2_RC_SUCCESS) {
        throw std::runtime_error("Esys_Sign failed: " + std::to_string(rc));
    }
    // Managing signature object using unique_ptr
    EsysUniquePtr<TPMT_SIGNATURE> signature(signatureRaw);

    // Encoding into ASN.1 DER format
    ECDSA_SIG *ecdsaSignature = ECDSA_SIG_new();

    BIGNUM *r_bn = BN_bin2bn(signature->signature.ecdsa.signatureR.buffer, signature->signature.ecdsa.signatureR.size, nullptr);
    BIGNUM *s_bn = BN_bin2bn(signature->signature.ecdsa.signatureS.buffer, signature->signature.ecdsa.signatureS.size, nullptr);
    ECDSA_SIG_set0(ecdsaSignature, r_bn, s_bn);
    int der_len = i2d_ECDSA_SIG(ecdsaSignature, nullptr);
    std::vector<uint8_t> der_signature(der_len);
    uint8_t* p = der_signature.data();
    i2d_ECDSA_SIG(ecdsaSignature, &p);
    ECDSA_SIG_free(ecdsaSignature);

    // RAII Guards automatically free pointers and calling Esys_FlushContext
    return der_signature;
}
