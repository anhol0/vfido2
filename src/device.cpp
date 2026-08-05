#include "device.hpp"
#include "error.hpp"
#include "uhid_report.hpp"
#include <cstdint>
#include <linux/uhid.h>
#include <stdexcept>
#include <unistd.h>

FIDODevice::FIDODevice() : 
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
    ev.u.create2.rd_size = fido_report_desc.size();

    ev.u.create2.bus = BUS_USB;
    ev.u.create2.vendor = 0x1234;
    ev.u.create2.product = 0x5678;

    int n = write(fd, &ev, sizeof(ev));
    if(n < 0) {
        throw std::runtime_error("Error writing to /dev/uhid");
    }
}

FIDODevice::~FIDODevice() {
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

uint32_t FIDODevice::get_type() {
    return ev.type;
}

std::vector<uint8_t> FIDODevice::get_data() {
     return std::vector<uint8_t>(ev.u.output.data, ev.u.output.data+ev.u.output.size);
}

void FIDODevice::send_err(CTAPError error, uint32_t cid) {
    CTAPPacket err_p;
    err_p.cmd = CTAPHID_ERROR;
    err_p.len = 1;
    err_p.cid = cid;
    err_p.payload.push_back(static_cast<uint8_t>(error));
    // Sendind err response
    auto resp = make_response(err_p);
    for(auto &r : resp) {
        send(r);
    }    
}

std::vector<uhid_event> make_response(UHIDReport &report) {
    CTAPPacket frame = respond(report);
    auto responses = frame.stringify();
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

std::vector<uhid_event> make_response(CTAPPacket &packet) {
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
