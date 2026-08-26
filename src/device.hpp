#pragma once

#include "error.hpp"
#include "credentials/credential.hpp"
#include "uhid_report.hpp"
#include "response.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <linux/uhid.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <cerrno>
#include <sys/types.h>
#include <unistd.h>
#include <vector>
#include <stop_token>

class FIDODevice {
public:
    FIDODevice();
    ~FIDODevice();
    void init();
    bool get();
    bool send(struct uhid_event &resp);

    int native_handle() const noexcept;

    uint32_t get_type();
    std::vector<uint8_t> get_data() const;
private:
    int fd = -1;
    struct uhid_event ev;
    const std::array<uint8_t, 34> fido_report_desc;
};

std::vector<uhid_event> frame_packet(CTAPPacket &packet);
CTAPPacket execute_ctap_request(
    UHIDReport report,
    std::stop_token stop,
    CredentialStore& store
);
CTAPPacket make_hid_error(uint32_t cid, HIDError error);
CTAPPacket make_cbor_error(uint32_t cid, CTAPError error);
