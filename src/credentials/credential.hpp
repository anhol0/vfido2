#pragma once

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
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
    bool discoverable = false;
    uint64_t creationOrder = 0;
};

class StoreGenerationCounter {
public:
    virtual ~StoreGenerationCounter() = default;
    [[nodiscard]] virtual uint64_t read() = 0;
    virtual void increment() = 0;
};

class CredentialStoreLock {
public:
    explicit CredentialStoreLock(const std::filesystem::path& store_path);
    ~CredentialStoreLock();

    CredentialStoreLock(const CredentialStoreLock&) = delete;
    CredentialStoreLock& operator=(const CredentialStoreLock&) = delete;

private:
    int directoryFd_ = -1;
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
#ifdef VFIDO_DEVELOPMENT_BUILD
    void clear();
#endif

    [[nodiscard]] bool has(const std::vector<uint8_t>& credId) const;
    [[nodiscard]] bool has_for_rp(
        const std::vector<uint8_t>& cred_id,
        std::string_view rp_id
    ) const;
    void put(const StoredCredential& cred);
    [[nodiscard]] const StoredCredential& get_by_credId(
        const std::vector<uint8_t>& credId
    ) const;
    [[nodiscard]] std::vector<StoredCredential> find_for_assertion(
        std::string_view rp_id,
        std::span<const PublicKeyCredentialDescriptor> allow_list
    ) const;
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
