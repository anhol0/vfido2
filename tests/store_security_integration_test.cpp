#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include "credentials/credential.hpp"
#include "cryptography/store_security.hpp"
#include "cryptography/tpm.hpp"

namespace {

struct PkeyDeleter {
    void operator()(EVP_PKEY* key) const noexcept {
        EVP_PKEY_free(key);
    }
};

struct PkeyContextDeleter {
    void operator()(EVP_PKEY_CTX* context) const noexcept {
        EVP_PKEY_CTX_free(context);
    }
};

using Pkey = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
using PkeyContext = std::unique_ptr<EVP_PKEY_CTX, PkeyContextDeleter>;

void verify_signature(
    const CredentialKey& key,
    const std::array<uint8_t, 32>& digest,
    const std::vector<uint8_t>& signature_bytes
) {
    const auto coordinates = extractPublic(key.publicBlob);
    std::array<uint8_t, 65> encoded_point{};
    encoded_point[0] = 0x04;
    std::copy(
        coordinates[0].begin(),
        coordinates[0].end(),
        encoded_point.begin() + 33 - coordinates[0].size()
    );
    std::copy(
        coordinates[1].begin(),
        coordinates[1].end(),
        encoded_point.begin() + 65 - coordinates[1].size()
    );
    std::array<char, 11> group_name{
        'p', 'r', 'i', 'm', 'e', '2', '5', '6', 'v', '1', '\0'
    };
    OSSL_PARAM parameters[]{
        OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_GROUP_NAME,
            group_name.data(),
            0
        ),
        OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY,
            encoded_point.data(),
            encoded_point.size()
        ),
        OSSL_PARAM_construct_end()
    };

    PkeyContext import_context(
        EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr)
    );
    EVP_PKEY* public_key_raw = nullptr;
    if(
        !import_context ||
        EVP_PKEY_fromdata_init(import_context.get()) != 1 ||
        EVP_PKEY_fromdata(
            import_context.get(),
            &public_key_raw,
            EVP_PKEY_PUBLIC_KEY,
            parameters
        ) != 1
    ) {
        throw std::runtime_error("Could not import test credential public key");
    }
    Pkey public_key(public_key_raw);
    PkeyContext verify_context(EVP_PKEY_CTX_new(public_key.get(), nullptr));
    if(
        !verify_context ||
        EVP_PKEY_verify_init(verify_context.get()) != 1 ||
        EVP_PKEY_CTX_set_signature_md(
            verify_context.get(), EVP_sha256()
        ) != 1 ||
        EVP_PKEY_verify(
            verify_context.get(),
            signature_bytes.data(),
            signature_bytes.size(),
            digest.data(),
            digest.size()
        ) != 1
    ) {
        throw std::runtime_error("TPM credential signature verification failed");
    }
}

std::vector<TPM2_HANDLE> persistent_handles(TSS2_TCTI_CONTEXT* tcti) {
    TpmCtx context(tcti);
    TPMI_YES_NO more_data = TPM2_NO;
    TPMS_CAPABILITY_DATA* capability_raw = nullptr;
    const TSS2_RC result = Esys_GetCapability(
        context.ctx,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        TPM2_CAP_HANDLES,
        TPM2_PERSISTENT_FIRST,
        TPM2_MAX_CAP_HANDLES,
        &more_data,
        &capability_raw
    );
    EsysUniquePtr<TPMS_CAPABILITY_DATA> capability(capability_raw);
    if(result != TSS2_RC_SUCCESS || capability == nullptr) {
        throw std::runtime_error("Could not enumerate persistent TPM handles");
    }
    if(more_data != TPM2_NO) {
        throw std::runtime_error("Persistent TPM handle test result was truncated");
    }

    const auto& handles = capability->data.handles;
    return {
        handles.handle,
        handles.handle + handles.count
    };
}

void test_transient_credential_parent(
    FapiStoreSecurity& security,
    const std::vector<uint8_t>& master_key
) {
    const auto before = persistent_handles(security.tcti());
    const std::vector<uint8_t> credential_id(32, 0xA7);
    const std::array<uint8_t, 32> digest{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    CredentialKey key;

    {
        CredentialKeyProvider provider(security.tcti(), master_key);
        key = provider.create(credential_id);
        verify_signature(
            key,
            digest,
            provider.sign(
                credential_id,
                digest,
                key.publicBlob,
                key.privateBlob
            )
        );

        auto wrong_id = credential_id;
        wrong_id.back() ^= 0x01;
        bool wrong_authorization_rejected = false;
        try {
            (void)provider.sign(
                wrong_id,
                digest,
                key.publicBlob,
                key.privateBlob
            );
        } catch(const std::exception&) {
            wrong_authorization_rejected = true;
        }
        if(!wrong_authorization_rejected) {
            throw std::runtime_error(
                "Credential key accepted authorization for a different ID"
            );
        }

        const auto expect_rejected = [](auto&& operation, const char* message) {
            try {
                operation();
            } catch(const std::exception&) {
                return;
            }
            throw std::runtime_error(message);
        };
        auto malformed_public = key.publicBlob;
        malformed_public.push_back(0);
        expect_rejected(
            [&] {
                (void)provider.sign(
                    credential_id,
                    digest,
                    malformed_public,
                    key.privateBlob
                );
            },
            "Credential public blob trailing data was accepted"
        );
        auto malformed_private = key.privateBlob;
        malformed_private.push_back(0);
        expect_rejected(
            [&] {
                (void)provider.sign(
                    credential_id,
                    digest,
                    key.publicBlob,
                    malformed_private
                );
            },
            "Credential private blob trailing data was accepted"
        );
        const std::array<uint8_t, 31> short_digest{};
        expect_rejected(
            [&] {
                (void)provider.sign(
                    credential_id,
                    short_digest,
                    key.publicBlob,
                    key.privateBlob
                );
            },
            "Non-SHA-256 credential digest size was accepted"
        );
    }

    {
        CredentialKeyProvider restarted(security.tcti(), master_key);
        verify_signature(
            key,
            digest,
            restarted.sign(
                credential_id,
                digest,
                key.publicBlob,
                key.privateBlob
            )
        );
    }

    {
        auto wrong_master = master_key;
        wrong_master.front() ^= 0x01;
        CredentialKeyProvider wrong_provider(security.tcti(), wrong_master);
        bool wrong_parent_rejected = false;
        try {
            (void)wrong_provider.sign(
                credential_id,
                digest,
                key.publicBlob,
                key.privateBlob
            );
        } catch(const std::exception&) {
            wrong_parent_rejected = true;
        }
        if(!wrong_parent_rejected) {
            throw std::runtime_error(
                "Credential blob loaded under a different derived parent"
            );
        }
    }

    const auto after = persistent_handles(security.tcti());
    if(after != before) {
        throw std::runtime_error(
            "Credential provider changed the persistent TPM handle set"
        );
    }
}

StoredCredential make_credential() {
    return StoredCredential{
        .id = std::vector<uint8_t>(16, 0x71),
        .rpId = "example.com",
        .userId = {0x01},
        .userName = "alice",
        .userDisplayName = "Alice",
        .alg = -7,
        .signCount = 0,
        .private_blob = {0x02},
        .public_blob = {0x03}
    };
}

void setup(
    const std::filesystem::path& store_path,
    const std::string& authorization,
    const std::string& wrong_authorization
) {
    FapiStoreSecurity security(authorization);
    security.provision();
    if(security.read() != 0) {
        throw std::runtime_error("New rollback counter is not zero");
    }

    const auto master_key = security.unseal_key();
    test_transient_credential_parent(security, master_key);

    {
        CredentialStore store(
            store_path,
            master_key,
            &security
        );
        store.load();
        store.put(make_credential());
    }
    if(security.read() != 1) {
        throw std::runtime_error("Rollback counter did not advance");
    }

    {
        CredentialStore reader(
            store_path,
            security.unseal_key(),
            &security
        );
        reader.load();
        if(!reader.has(make_credential().id)) {
            throw std::runtime_error("Credential did not round-trip");
        }
    }

    {
        CredentialStore cleaner(
            store_path,
            security.unseal_key(),
            &security
        );
        cleaner.load();
        cleaner.clear();
    }
    if(security.read() != 2) {
        throw std::runtime_error("Store clear did not advance rollback counter");
    }
    if(security.unseal_key() != master_key) {
        throw std::runtime_error("Store clear replaced the sealed database key");
    }
    {
        CredentialStore reader(
            store_path,
            security.unseal_key(),
            &security
        );
        reader.load();
        if(reader.has(make_credential().id)) {
            throw std::runtime_error("Credential remained after store clear");
        }
    }

    bool wrong_authorization_rejected = false;
    try {
        FapiStoreSecurity wrong_security(wrong_authorization);
        (void)wrong_security.unseal_key();
    } catch(const std::exception&) {
        wrong_authorization_rejected = true;
    }
    if(!wrong_authorization_rejected) {
        throw std::runtime_error("Wrong authorization was accepted");
    }
}

void verify_tpm_clear_is_rejected(const std::string& authorization) {
    bool rejected = false;
    try {
        FapiStoreSecurity security(authorization);
        (void)security.unseal_key();
    } catch(const std::exception&) {
        rejected = true;
    }
    if(!rejected) {
        throw std::runtime_error("TPM clear did not invalidate the sealed key");
    }
}

} // namespace

int main(int argc, char** argv) {
    try {
        if(argc < 3) {
            throw std::invalid_argument("Missing integration test arguments");
        }
        const std::string mode = argv[1];
        if(mode == "setup" && argc == 5) {
            setup(argv[2], argv[3], argv[4]);
        } else if(mode == "verify-tpm-clear" && argc == 3) {
            verify_tpm_clear_is_rejected(argv[2]);
        } else {
            throw std::invalid_argument("Invalid integration test arguments");
        }
    } catch(const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
