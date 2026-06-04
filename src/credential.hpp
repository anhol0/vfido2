#pragma once 

#include <sys/types.h>
#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>
#include <vector>

static const std::string CRED_STORE_PATH="/etc/vfido2/cred.json";

typedef struct StoredCredential {
    std::vector<uint8_t> id;
    std::string rpId;
    std::vector<uint8_t> userId;
    int32_t alg;
    uint32_t signCount;
    std::vector<uint8_t> private_blob;
    std::vector<uint8_t> public_blob;
} StoredCredential;

class CredentialStore {
    public:
        void init();
        void load();
        void save();

        bool has(const std::vector<uint8_t> &credId) const;
        void put(const StoredCredential &cred);
        const StoredCredential& get(const std::vector<uint8_t> &credId) const;
        void incrementSigCount(const std::vector<uint8_t> &credId);
        std::string toHex(const std::vector<uint8_t> &v) const;
        std::vector<uint8_t> fromHex(const std::string &s);
        int signCounter = 0;

    private:
        std::vector<uint8_t> decrypt(std::vector<uint8_t> &ciphertext);
        std::vector<uint8_t> encrypt(std::vector<uint8_t> &plaintext);
        std::unordered_map<std::string, StoredCredential> stored_;
        std::vector<uint8_t> storeKey_;
};

