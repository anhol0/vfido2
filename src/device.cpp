#include "device.hpp"
#include "cancellation.hpp"
#include "error.hpp"
#include "response.hpp"
#include "uhid_report.hpp"
#include <cstdint>
#include <linux/uhid.h>
#include <stdexcept>
#include <stop_token>
#include <system_error>
#include <unistd.h>

FIDODevice::FIDODevice() :
    // FIDO report descriptor
    // It tells the system that the device is actually a FIDO device, not any other HID device
    // It is needed only for uhid kernel module to recognize the device
    fido_report_desc{{
        0x06, 0xD0, 0xF1,        // Usage Page (FIDO 0xF1D0)
        0x09, 0x01,              // Usage (U2F HID Authenticator Device)
        0xA1, 0x01,              // Collection (Application)

        0x09, 0x20,              // Usage (Input Report Data)
        0x15, 0x00,              // Logical Minimum (0)
        0x26, 0xFF, 0x00,        // Logical Maximum (255)
        0x75, 0x08,              // Report Size (8 bits)
        0x95, 0x40,              // Report Count (64 bytes)
        0x81, 0x02,              // Input (Data,Var,Abs)

        0x09, 0x21,              // Usage (Output Report Data)
        0x15, 0x00,
        0x26, 0xFF, 0x00,
        0x75, 0x08,
        0x95, 0x40,
        0x91, 0x02,              // Output (Data,Var,Abs)

        0xC0                     // End Collection
}}{}

void FIDODevice::init() {
    fd = open("/dev/uhid", O_RDWR);
    if (fd < 0) {
        throw std::runtime_error("Error opening /dev/uhid");
    }

    memset(&ev, 0, sizeof(ev));

    // Device creation event
    ev.type = UHID_CREATE2;

    memcpy(ev.u.create2.rd_data, fido_report_desc.data(), fido_report_desc.size());
    strncpy((char*)ev.u.create.name, "vFIDO2-Keyring", sizeof(ev.u.create.name) - 1);

    ev.u.create2.rd_size = fido_report_desc.size();

    ev.u.create2.bus = BUS_USB;
    ev.u.create2.vendor = 0x1234;
    ev.u.create2.product = 0x5678;

    int n = write(fd, &ev, sizeof(ev));
    if(n < 0) {
        throw std::system_error(errno, std::generic_category(), "Error writing to /dev/uhid");
    }
}

FIDODevice::~FIDODevice() {
    if(fd >= 0)
        close(fd);
}

bool FIDODevice::get() {
    ssize_t n = read(fd, &ev, sizeof(ev));
    if(n <= 0)
        return false;
    return true;
}

bool FIDODevice::send(struct uhid_event &resp) {
    int n = write(fd, &resp, sizeof(resp));
    if(n <= 0)
        return false;
    return true;
}

int FIDODevice::native_handle() const noexcept {
    return fd;
}

uint32_t FIDODevice::get_type() {
    return ev.type;
}

std::vector<uint8_t> FIDODevice::get_data() const {
     return std::vector<uint8_t>(ev.u.output.data, ev.u.output.data+ev.u.output.size);
}

CTAPPacket make_cbor_error(uint32_t cid, CTAPError error)
{
    CTAPPacket packet;
    packet.cid = cid;
    packet.cmd = CTAPHID_CBOR | MASK;
    packet.payload = {static_cast<uint8_t>(error)};
    packet.len = packet.payload.size();
    return packet;
}

CTAPPacket make_hid_error(uint32_t cid, HIDError error)
{
    CTAPPacket packet;
    packet.cid = cid;
    packet.cmd = CTAPHID_ERROR | MASK;
    packet.payload = {static_cast<uint8_t>(error)};
    packet.len = packet.payload.size();
    return packet;
}

CTAPPacket execute_ctap_request(
    UHIDReport report,
    std::stop_token stop,
    CredentialStore& store,
    CredentialKeyProvider& key_provider,
    KeepaliveState& keepalive
) {
    cancellation_point(stop);
    return handle_cbor(report, stop, store, key_provider, keepalive);
}

std::vector<uhid_event> frame_packet(CTAPPacket &packet) {
    auto responses = packet.stringify();
    std::vector<uhid_event> packets;
    for(const auto &response : responses) {
        struct uhid_event resp;
        memset(&resp, 0, sizeof(resp));
        resp.type = UHID_INPUT2;
        memcpy(resp.u.input2.data, response.data(), response.size());
        resp.u.input2.size = response.size();
        packets.push_back(resp);
    }
    return packets;
}
