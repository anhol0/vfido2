#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stop_token>
#include <vector>

#include "credentials/credential.hpp"
#include "uhid_report.hpp"

class CredentialKeyProvider;
class KeepaliveState;

constexpr uint8_t MASK = 0x80;

enum {
    CTAPHID_PING      = 0x01,
    CTAPHID_MSG       = 0x03,
    CTAPHID_LOCK      = 0x04,
    CTAPHID_INIT      = 0x06,
    CTAPHID_WINK      = 0x08,
    CTAPHID_CBOR      = 0x10,
    CTAPHID_CANCEL    = 0x11,
    CTAPHID_KEEPALIVE = 0x3B,
    CTAPHID_ERROR     = 0x3f,
};

class CTAPPacket {
public:
    uint32_t cid = 0;
    uint8_t  cmd = 0;
    uint16_t len = 0;
    std::vector<uint8_t> payload;

    std::vector<std::vector<uint8_t>> stringify();
};

CTAPPacket handle_init(UHIDReport &request, uint32_t assigned_cid);
CTAPPacket handle_ping(UHIDReport &request);
void start_worker(UHIDReport &request);
CTAPPacket handle_cbor(
    UHIDReport& request,
    std::stop_token stop,
    CredentialStore& store,
    CredentialKeyProvider& key_provider,
    KeepaliveState& keepalive
);
