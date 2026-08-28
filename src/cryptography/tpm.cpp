#include "tpm.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tpm2_types.h>

#include "cryptography/crypto.hpp"

namespace {

constexpr std::size_t AUTHORIZATION_SIZE = 32;
constexpr std::size_t CREDENTIAL_ID_MIN_SIZE = 16;
constexpr std::size_t CREDENTIAL_ID_MAX_SIZE = 1024;
constexpr std::size_t SHA256_SIZE = 32;
constexpr std::string_view PARENT_AUTH_LABEL =
    "vfido2 transient parent authorization v1";
constexpr std::string_view CREDENTIAL_MASTER_LABEL =
    "vfido2 credential authorization master v1";
constexpr std::string_view CREDENTIAL_AUTH_LABEL =
    "vfido2 credential authorization v1";
constexpr TPMA_OBJECT PARENT_ATTRIBUTES =
    TPMA_OBJECT_FIXEDTPM |
    TPMA_OBJECT_FIXEDPARENT |
    TPMA_OBJECT_SENSITIVEDATAORIGIN |
    TPMA_OBJECT_USERWITHAUTH |
    TPMA_OBJECT_NODA |
    TPMA_OBJECT_RESTRICTED |
    TPMA_OBJECT_DECRYPT;
constexpr TPMA_OBJECT CREDENTIAL_ATTRIBUTES =
    TPMA_OBJECT_SIGN_ENCRYPT |
    TPMA_OBJECT_FIXEDTPM |
    TPMA_OBJECT_FIXEDPARENT |
    TPMA_OBJECT_SENSITIVEDATAORIGIN |
    TPMA_OBJECT_USERWITHAUTH |
    TPMA_OBJECT_NODA;

struct PkeyContextDeleter {
    void operator()(EVP_PKEY_CTX* context) const noexcept {
        EVP_PKEY_CTX_free(context);
    }
};

using PkeyContext = std::unique_ptr<EVP_PKEY_CTX, PkeyContextDeleter>;

template<typename T>
class CleanseObject {
public:
    explicit CleanseObject(T& value) noexcept : value_(value) {}
    ~CleanseObject() {
        OPENSSL_cleanse(&value_, sizeof(value_));
    }

    CleanseObject(const CleanseObject&) = delete;
    CleanseObject& operator=(const CleanseObject&) = delete;

private:
    T& value_;
};

[[noreturn]] void throw_tpm_error(TSS2_RC result, std::string operation) {
    throw std::runtime_error(
        std::move(operation) + " failed: " + Tss2_RC_Decode(result)
    );
}

void tpm_check(TSS2_RC result, std::string_view operation) {
    if(result != TSS2_RC_SUCCESS) {
        throw_tpm_error(result, std::string(operation));
    }
}

std::array<uint8_t, AUTHORIZATION_SIZE> derive_key(
    std::span<const uint8_t> input_key,
    std::string_view label,
    std::span<const uint8_t> context = {}
) {
    if(input_key.empty()) {
        throw std::invalid_argument("HKDF input key must not be empty");
    }

    PkeyContext kdf(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    if(!kdf) {
        throw std::runtime_error("EVP_PKEY_CTX_new_id HKDF failed");
    }
    openssl_check(EVP_PKEY_derive_init(kdf.get()), "EVP_PKEY_derive_init HKDF");
    openssl_check(
        EVP_PKEY_CTX_set_hkdf_md(kdf.get(), EVP_sha256()),
        "EVP_PKEY_CTX_set_hkdf_md"
    );
    openssl_check(
        EVP_PKEY_CTX_set1_hkdf_key(
            kdf.get(),
            input_key.data(),
            openssl_checked_size(input_key.size(), "HKDF input key")
        ),
        "EVP_PKEY_CTX_set1_hkdf_key"
    );
    openssl_check(
        EVP_PKEY_CTX_add1_hkdf_info(
            kdf.get(),
            reinterpret_cast<const uint8_t*>(label.data()),
            openssl_checked_size(label.size(), "HKDF label")
        ),
        "EVP_PKEY_CTX_add1_hkdf_info label"
    );
    if(!context.empty()) {
        openssl_check(
            EVP_PKEY_CTX_add1_hkdf_info(
                kdf.get(),
                context.data(),
                openssl_checked_size(context.size(), "HKDF context")
            ),
            "EVP_PKEY_CTX_add1_hkdf_info context"
        );
    }

    std::array<uint8_t, AUTHORIZATION_SIZE> output{};
    std::size_t output_size = output.size();
    openssl_check(
        EVP_PKEY_derive(kdf.get(), output.data(), &output_size),
        "EVP_PKEY_derive HKDF"
    );
    if(output_size != output.size()) {
        OPENSSL_cleanse(output.data(), output.size());
        throw std::runtime_error("HKDF returned an unexpected output size");
    }
    return output;
}

TPM2B_PUBLIC parent_template() {
    TPM2B_PUBLIC result{};
    auto& public_area = result.publicArea;
    public_area.type = TPM2_ALG_ECC;
    public_area.nameAlg = TPM2_ALG_SHA256;
    public_area.objectAttributes = PARENT_ATTRIBUTES;
    public_area.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_AES;
    public_area.parameters.eccDetail.symmetric.keyBits.aes = 128;
    public_area.parameters.eccDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    public_area.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
    public_area.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
    public_area.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
    return result;
}

TPM2B_PUBLIC credential_template() {
    TPM2B_PUBLIC result{};
    auto& public_area = result.publicArea;
    public_area.type = TPM2_ALG_ECC;
    public_area.nameAlg = TPM2_ALG_SHA256;
    public_area.objectAttributes = CREDENTIAL_ATTRIBUTES;
    public_area.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
    public_area.parameters.eccDetail.scheme.scheme = TPM2_ALG_ECDSA;
    public_area.parameters.eccDetail.scheme.details.ecdsa.hashAlg =
        TPM2_ALG_SHA256;
    public_area.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
    public_area.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
    return result;
}

void set_auth(
    ESYS_CONTEXT* context,
    ESYS_TR handle,
    std::span<const uint8_t, AUTHORIZATION_SIZE> authorization
) {
    TPM2B_AUTH auth{};
    CleanseObject cleanse_auth(auth);
    auth.size = static_cast<uint16_t>(authorization.size());
    std::copy(authorization.begin(), authorization.end(), auth.buffer);
    tpm_check(Esys_TR_SetAuth(context, handle, &auth), "Esys_TR_SetAuth");
}

void validate_credential_id(std::span<const uint8_t> credential_id) {
    if(
        credential_id.size() < CREDENTIAL_ID_MIN_SIZE ||
        credential_id.size() > CREDENTIAL_ID_MAX_SIZE
    ) {
        throw std::invalid_argument(
            "Credential ID must contain between 16 and 1024 bytes"
        );
    }
}

TPM2B_PUBLIC unmarshal_public(std::span<const uint8_t> blob) {
    TPM2B_PUBLIC result{};
    std::size_t offset = 0;
    tpm_check(
        Tss2_MU_TPM2B_PUBLIC_Unmarshal(
            blob.data(), blob.size(), &offset, &result
        ),
        "Tss2_MU_TPM2B_PUBLIC_Unmarshal"
    );
    if(offset != blob.size()) {
        throw std::runtime_error("TPM public blob contains trailing data");
    }
    return result;
}

TPM2B_PRIVATE unmarshal_private(std::span<const uint8_t> blob) {
    TPM2B_PRIVATE result{};
    std::size_t offset = 0;
    tpm_check(
        Tss2_MU_TPM2B_PRIVATE_Unmarshal(
            blob.data(), blob.size(), &offset, &result
        ),
        "Tss2_MU_TPM2B_PRIVATE_Unmarshal"
    );
    if(offset != blob.size()) {
        throw std::runtime_error("TPM private blob contains trailing data");
    }
    return result;
}

void validate_parent_public(const TPM2B_PUBLIC& public_blob) {
    const auto& public_area = public_blob.publicArea;
    const auto& parameters = public_area.parameters.eccDetail;
    const auto& point = public_area.unique.ecc;
    if(
        public_area.type != TPM2_ALG_ECC ||
        public_area.nameAlg != TPM2_ALG_SHA256 ||
        public_area.objectAttributes != PARENT_ATTRIBUTES ||
        public_area.authPolicy.size != 0 ||
        parameters.symmetric.algorithm != TPM2_ALG_AES ||
        parameters.symmetric.keyBits.aes != 128 ||
        parameters.symmetric.mode.aes != TPM2_ALG_CFB ||
        parameters.scheme.scheme != TPM2_ALG_NULL ||
        parameters.curveID != TPM2_ECC_NIST_P256 ||
        parameters.kdf.scheme != TPM2_ALG_NULL ||
        point.x.size == 0 || point.x.size > SHA256_SIZE ||
        point.y.size == 0 || point.y.size > SHA256_SIZE
    ) {
        throw std::runtime_error("TPM parent public area has invalid parameters");
    }
}

void validate_public_key(const TPM2B_PUBLIC& public_blob) {
    const auto& public_area = public_blob.publicArea;
    const auto& parameters = public_area.parameters.eccDetail;
    const auto& point = public_area.unique.ecc;
    if(
        public_area.type != TPM2_ALG_ECC ||
        public_area.nameAlg != TPM2_ALG_SHA256 ||
        public_area.objectAttributes != CREDENTIAL_ATTRIBUTES ||
        public_area.authPolicy.size != 0 ||
        parameters.symmetric.algorithm != TPM2_ALG_NULL ||
        parameters.scheme.scheme != TPM2_ALG_ECDSA ||
        parameters.scheme.details.ecdsa.hashAlg != TPM2_ALG_SHA256 ||
        parameters.curveID != TPM2_ECC_NIST_P256 ||
        parameters.kdf.scheme != TPM2_ALG_NULL ||
        point.x.size == 0 || point.x.size > SHA256_SIZE ||
        point.y.size == 0 || point.y.size > SHA256_SIZE
    ) {
        throw std::runtime_error("TPM credential public blob has invalid parameters");
    }
}

std::vector<uint8_t> marshal_public(const TPM2B_PUBLIC& value) {
    const std::size_t capacity = sizeof(value.size) + value.size;
    std::vector<uint8_t> output(capacity);
    std::size_t offset = 0;
    tpm_check(
        Tss2_MU_TPM2B_PUBLIC_Marshal(
            &value, output.data(), output.size(), &offset
        ),
        "Tss2_MU_TPM2B_PUBLIC_Marshal"
    );
    if(offset != output.size()) {
        throw std::runtime_error("TPM public blob marshalled to an invalid size");
    }
    return output;
}

std::vector<uint8_t> marshal_private(const TPM2B_PRIVATE& value) {
    const std::size_t capacity = sizeof(value.size) + value.size;
    std::vector<uint8_t> output(capacity);
    std::size_t offset = 0;
    tpm_check(
        Tss2_MU_TPM2B_PRIVATE_Marshal(
            &value, output.data(), output.size(), &offset
        ),
        "Tss2_MU_TPM2B_PRIVATE_Marshal"
    );
    if(offset != output.size()) {
        throw std::runtime_error("TPM private blob marshalled to an invalid size");
    }
    return output;
}

} // namespace

TpmCtx::TpmCtx(TSS2_TCTI_CONTEXT* tcti) {
    const TSS2_RC result = Esys_Initialize(&ctx, tcti, nullptr);
    if(result != TSS2_RC_SUCCESS) {
        if(ctx != nullptr) {
            Esys_Finalize(&ctx);
        }
        throw_tpm_error(result, "Esys_Initialize");
    }
}

TpmCtx::~TpmCtx() {
    if(ctx != nullptr) {
        Esys_Finalize(&ctx);
    }
}

CredentialKeyProvider::Secret::~Secret() {
    OPENSSL_cleanse(bytes.data(), bytes.size());
}

CredentialKeyProvider::CredentialKeyProvider(
    TSS2_TCTI_CONTEXT* tcti,
    std::span<const uint8_t> master_key
) :
    tpm_(tcti),
    parent_(tpm_.ctx)
{
    if(master_key.size() != AUTHORIZATION_SIZE) {
        throw std::invalid_argument("Credential master key must be 32 bytes");
    }
    parentAuthorization_.bytes = derive_key(master_key, PARENT_AUTH_LABEL);
    credentialAuthorizationMaster_.bytes = derive_key(
        master_key,
        CREDENTIAL_MASTER_LABEL
    );

    TPM2B_SENSITIVE_CREATE sensitive{};
    CleanseObject cleanse_sensitive(sensitive);
    sensitive.sensitive.userAuth.size = static_cast<uint16_t>(
        parentAuthorization_.bytes.size()
    );
    std::copy(
        parentAuthorization_.bytes.begin(),
        parentAuthorization_.bytes.end(),
        sensitive.sensitive.userAuth.buffer
    );

    const TPM2B_PUBLIC public_template = parent_template();
    const TPM2B_DATA outside_info{};
    const TPML_PCR_SELECTION creation_pcr{};
    TPM2B_PUBLIC* out_public_raw = nullptr;
    TPM2B_CREATION_DATA* creation_data_raw = nullptr;
    TPM2B_DIGEST* creation_hash_raw = nullptr;
    TPMT_TK_CREATION* creation_ticket_raw = nullptr;

    const TSS2_RC result = Esys_CreatePrimary(
        tpm_.ctx,
        ESYS_TR_RH_OWNER,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &sensitive,
        &public_template,
        &outside_info,
        &creation_pcr,
        parent_.ptr(),
        &out_public_raw,
        &creation_data_raw,
        &creation_hash_raw,
        &creation_ticket_raw
    );
    EsysUniquePtr<TPM2B_PUBLIC> out_public(out_public_raw);
    EsysUniquePtr<TPM2B_CREATION_DATA> creation_data(creation_data_raw);
    EsysUniquePtr<TPM2B_DIGEST> creation_hash(creation_hash_raw);
    EsysUniquePtr<TPMT_TK_CREATION> creation_ticket(creation_ticket_raw);
    tpm_check(result, "Esys_CreatePrimary credential parent");
    if(out_public == nullptr) {
        throw std::runtime_error("Esys_CreatePrimary returned no parent public area");
    }
    validate_parent_public(*out_public);

    set_auth(tpm_.ctx, parent_.get(), parentAuthorization_.bytes);
}

CredentialKeyProvider::~CredentialKeyProvider() = default;

std::array<uint8_t, AUTHORIZATION_SIZE>
CredentialKeyProvider::credential_authorization(
    std::span<const uint8_t> credential_id
) const {
    validate_credential_id(credential_id);
    return derive_key(
        credentialAuthorizationMaster_.bytes,
        CREDENTIAL_AUTH_LABEL,
        credential_id
    );
}

CredentialKey CredentialKeyProvider::create(
    std::span<const uint8_t> credential_id
) {
    auto authorization = credential_authorization(credential_id);
    CleanseObject cleanse_authorization(authorization);

    TPM2B_SENSITIVE_CREATE sensitive{};
    CleanseObject cleanse_sensitive(sensitive);
    sensitive.sensitive.userAuth.size = static_cast<uint16_t>(
        authorization.size()
    );
    std::copy(
        authorization.begin(),
        authorization.end(),
        sensitive.sensitive.userAuth.buffer
    );

    const TPM2B_PUBLIC public_template = credential_template();
    const TPM2B_DATA outside_info{};
    const TPML_PCR_SELECTION creation_pcr{};
    TPM2B_PRIVATE* private_raw = nullptr;
    TPM2B_PUBLIC* public_raw = nullptr;
    TPM2B_CREATION_DATA* creation_data_raw = nullptr;
    TPM2B_DIGEST* creation_hash_raw = nullptr;
    TPMT_TK_CREATION* creation_ticket_raw = nullptr;
    const TSS2_RC result = Esys_Create(
        tpm_.ctx,
        parent_.get(),
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &sensitive,
        &public_template,
        &outside_info,
        &creation_pcr,
        &private_raw,
        &public_raw,
        &creation_data_raw,
        &creation_hash_raw,
        &creation_ticket_raw
    );
    EsysUniquePtr<TPM2B_PRIVATE> private_blob(private_raw);
    EsysUniquePtr<TPM2B_PUBLIC> public_blob(public_raw);
    EsysUniquePtr<TPM2B_CREATION_DATA> creation_data(creation_data_raw);
    EsysUniquePtr<TPM2B_DIGEST> creation_hash(creation_hash_raw);
    EsysUniquePtr<TPMT_TK_CREATION> creation_ticket(creation_ticket_raw);
    tpm_check(result, "Esys_Create credential key");
    if(private_blob == nullptr || public_blob == nullptr) {
        throw std::runtime_error("Esys_Create returned incomplete key blobs");
    }
    validate_public_key(*public_blob);

    return CredentialKey{
        .publicBlob = marshal_public(*public_blob),
        .privateBlob = marshal_private(*private_blob)
    };
}

std::vector<uint8_t> CredentialKeyProvider::sign(
    std::span<const uint8_t> credential_id,
    std::span<const uint8_t> digest_bytes,
    std::span<const uint8_t> public_blob_bytes,
    std::span<const uint8_t> private_blob_bytes
) {
    if(digest_bytes.size() != SHA256_SIZE) {
        throw std::invalid_argument("Credential digest must contain 32 bytes");
    }

    auto authorization = credential_authorization(credential_id);
    CleanseObject cleanse_authorization(authorization);
    TPM2B_PUBLIC public_blob = unmarshal_public(public_blob_bytes);
    validate_public_key(public_blob);
    TPM2B_PRIVATE private_blob = unmarshal_private(private_blob_bytes);
    CleanseObject cleanse_private_blob(private_blob);

    TpmTransientHandle key_handle(tpm_.ctx);
    tpm_check(
        Esys_Load(
            tpm_.ctx,
            parent_.get(),
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &private_blob,
            &public_blob,
            key_handle.ptr()
        ),
        "Esys_Load credential key"
    );
    set_auth(tpm_.ctx, key_handle.get(), authorization);

    TPM2B_DIGEST digest{};
    digest.size = static_cast<uint16_t>(digest_bytes.size());
    std::copy(digest_bytes.begin(), digest_bytes.end(), digest.buffer);
    const TPMT_SIG_SCHEME scheme{
        .scheme = TPM2_ALG_ECDSA,
        .details = {.ecdsa = {.hashAlg = TPM2_ALG_SHA256}}
    };
    const TPMT_TK_HASHCHECK validation{
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_NULL,
        .digest = {0}
    };

    TPMT_SIGNATURE* signature_raw = nullptr;
    const TSS2_RC result = Esys_Sign(
        tpm_.ctx,
        key_handle.get(),
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &digest,
        &scheme,
        &validation,
        &signature_raw
    );
    EsysUniquePtr<TPMT_SIGNATURE> signature(signature_raw);
    tpm_check(result, "Esys_Sign credential assertion");
    if(
        signature == nullptr ||
        signature->sigAlg != TPM2_ALG_ECDSA ||
        signature->signature.ecdsa.hash != TPM2_ALG_SHA256 ||
        signature->signature.ecdsa.signatureR.size == 0 ||
        signature->signature.ecdsa.signatureR.size > SHA256_SIZE ||
        signature->signature.ecdsa.signatureS.size == 0 ||
        signature->signature.ecdsa.signatureS.size > SHA256_SIZE
    ) {
        throw std::runtime_error("TPM returned an invalid ECDSA signature");
    }

    auto ecdsa_signature = openssl_make_ecdsa_signature();
    auto r = openssl_make_big_number({
        signature->signature.ecdsa.signatureR.buffer,
        signature->signature.ecdsa.signatureR.size
    });
    auto s = openssl_make_big_number({
        signature->signature.ecdsa.signatureS.buffer,
        signature->signature.ecdsa.signatureS.size
    });
    openssl_check(
        ECDSA_SIG_set0(ecdsa_signature.get(), r.get(), s.get()),
        "ECDSA_SIG_set0"
    );
    (void)r.release();
    (void)s.release();

    const int der_size = i2d_ECDSA_SIG(ecdsa_signature.get(), nullptr);
    openssl_check_positive(der_size, "i2d_ECDSA_SIG size");
    std::vector<uint8_t> der_signature(static_cast<std::size_t>(der_size));
    uint8_t* output = der_signature.data();
    const int encoded_size = i2d_ECDSA_SIG(ecdsa_signature.get(), &output);
    openssl_check_positive(encoded_size, "i2d_ECDSA_SIG encode");
    if(encoded_size != der_size) {
        throw std::runtime_error("i2d_ECDSA_SIG returned an inconsistent size");
    }
    return der_signature;
}

std::array<std::vector<uint8_t>, 2> extractPublic(
    std::span<const uint8_t> public_blob_bytes
) {
    const TPM2B_PUBLIC public_blob = unmarshal_public(public_blob_bytes);
    validate_public_key(public_blob);
    const auto& point = public_blob.publicArea.unique.ecc;

    return {
        std::vector<uint8_t>(point.x.buffer, point.x.buffer + point.x.size),
        std::vector<uint8_t>(point.y.buffer, point.y.buffer + point.y.size)
    };
}
