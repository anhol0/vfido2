#pragma once

#include <filesystem>
#include <sys/types.h>
#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>
#include <vector>
#include <nlohmann/json.hpp>

typedef struct PublicKeyCredentialDescriptor {
    std::string type;
    std::vector<uint8_t> id;
    std::vector<std::string> transports;
} PublicKeyCredentialDescriptor;


typedef struct StoredCredential {
    std::vector<uint8_t> id;
    std::string rpId;
    std::vector<uint8_t> userId;
    std::string userName;
    std::string userDisplayName;
    int32_t alg;
    uint32_t signCount;
    std::vector<uint8_t> private_blob;
    std::vector<uint8_t> public_blob;
} StoredCredential;

class CredentialStore {
    public:
        using Key = const std::vector<uint8_t>;
        using Storage = std::unordered_map<std::string, StoredCredential>;
        CredentialStore(std::filesystem::path path, Key key);
        void load();

        bool has(const std::vector<uint8_t> &credId) const;
        void put(const StoredCredential &cred);
        const StoredCredential& get_by_credId(const std::vector<uint8_t> &credId) const;
        const Storage get_all_creds() const;
        void incrementSigCount(const std::vector<uint8_t> &credId);
        std::string toHex(const std::vector<uint8_t> &v) const;
        std::vector<uint8_t> fromHex(const std::string &s);

        private:
        Storage stored_;
        std::vector<uint8_t> decrypt(std::vector<uint8_t> &ciphertext);
        std::vector<uint8_t> encrypt(std::vector<uint8_t> &plaintext);
        void save();
        void save_storage(const Storage& storage);

        Storage parse_storage(const nlohmann::json &json);

        std::filesystem::path storePath_;
        Key storeKey_;
        int signCounter = 0;
};
