#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

struct PublicKeyCredentialDescriptor {
    std::string type;
    std::vector<uint8_t> id;
    std::vector<std::string> transports;
};


struct StoredCredential {
    std::vector<uint8_t> id;
    std::string rpId;
    std::vector<uint8_t> userId;
    std::string userName;
    std::string userDisplayName;
    int32_t alg;
    uint32_t signCount;
    std::vector<uint8_t> private_blob;
    std::vector<uint8_t> public_blob;
};

class StoreGenerationCounter {
public:
    virtual ~StoreGenerationCounter() = default;
    [[nodiscard]] virtual uint64_t read() = 0;
    virtual void increment() = 0;
};

class CredentialStore {
public:
    using Key = std::vector<uint8_t>;
    using Storage = std::unordered_map<std::string, StoredCredential>;

    CredentialStore(
        std::filesystem::path path,
        Key key,
        StoreGenerationCounter* generation_counter = nullptr
    );
    ~CredentialStore();
    void load();

    static void migrate_legacy(
        const std::filesystem::path& legacy_path,
        const std::filesystem::path& new_path,
        Key legacy_key,
        Key new_key,
        StoreGenerationCounter& generation_counter
    );

    [[nodiscard]] bool has(const std::vector<uint8_t>& credId) const;
    void put(const StoredCredential& cred);
    [[nodiscard]] const StoredCredential& get_by_credId(
        const std::vector<uint8_t>& credId
    ) const;
    [[nodiscard]] Storage get_all_creds() const;
    void incrementSigCount(const std::vector<uint8_t>& credId);
    [[nodiscard]] std::string toHex(const std::vector<uint8_t>& v) const;
    [[nodiscard]] std::vector<uint8_t> fromHex(const std::string& s) const;

private:
    struct DecryptedStore {
        uint64_t generation;
        std::vector<uint8_t> plaintext;
    };

    [[nodiscard]] DecryptedStore decrypt(
        const std::vector<uint8_t>& ciphertext
    ) const;
    [[nodiscard]] std::vector<uint8_t> encrypt(
        const std::vector<uint8_t>& plaintext,
        uint64_t generation
    ) const;
    void save_storage(const Storage& storage);
    [[nodiscard]] Storage parse_storage(const nlohmann::json& json) const;

    Storage stored_;
    std::filesystem::path storePath_;
    Key storeKey_;
    StoreGenerationCounter* generationCounter_;
    uint64_t generation_ = 0;
    bool requiresReload_ = false;
};
