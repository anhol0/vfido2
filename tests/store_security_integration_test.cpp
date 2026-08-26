#include <cstdint>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "credentials/credential.hpp"
#include "cryptography/store_security.hpp"

namespace {

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

    {
        CredentialStore store(
            store_path,
            security.unseal_key(),
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
