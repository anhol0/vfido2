#ifndef RESPONSE_HPP
#define RESPONSE_HPP

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "uhid_report.hpp"

#define MASK 0x80

enum {
    CTAPHID_MSG = 0x03,
    CTAPHID_CBOR = 0x10,
    CTAPHID_INIT = 0x06,
    CTAPHID_PING = 0x01,
    CTAPHID_WINK = 0x08,
    CTAPHID_LOCK = 0x04,
    CTAPHID_CANCEL = 0x11,
    CTAPHID_ERROR = 0x3f,
};

class CTAPPacket {
public:
    uint32_t cid;
    uint8_t  cmd = 0x00;
    uint16_t len;

    std::vector<uint8_t> payload;
    std::vector<std::vector<uint8_t>> stringify();
};

uint32_t gen_cid();
CTAPPacket respond(UHIDReport &r);

#endif
