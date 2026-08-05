#ifndef DEVICE_HPP
#define DEVICE_HPP

#include "uhid_report.hpp"
#include "response.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <linux/uhid.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <cerrno>
#include <string.h>
#include <unistd.h>
#include <stdexcept>
#include <vector>

class FIDODevice {
public:
    FIDODevice();
    void init();
    bool get();
    bool send(struct uhid_event &resp); 
    uint32_t get_type();
    std::vector<uint8_t> get_data();
private:
    size_t fd;
    struct uhid_event ev;
    const std::array<uint8_t, 34> fido_report_desc;
};

inline FIDODevice::FIDODevice() : 
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

void inline FIDODevice::init() {
    fd = open("/dev/uhid", O_RDWR);
    if (fd < 0) {
        perror("open /dev/uhid");
        std::runtime_error("Error opening /dev/uhid");
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
        perror("write to /dev/uhid");
        std::runtime_error("Error writing to /dev/uhid");
    }
}

inline bool FIDODevice::get() {  
    ssize_t n = read(fd, &ev, sizeof(ev));
    if(n <= 0) 
        return false; 
    return true;
}

inline bool FIDODevice::send(struct uhid_event &resp) {
    int n = write(fd, &resp, sizeof(resp));
    if(n <= 0)
        return false;
    return true;
}

inline uint32_t FIDODevice::get_type() {
    return ev.type;
}

inline std::vector<uint8_t> FIDODevice::get_data() {
     return std::vector<uint8_t>(ev.u.output.data, ev.u.output.data+ev.u.output.size);
}

inline uhid_event make_response(UHIDReport &report) {
    struct uhid_event resp;
    memset(&resp, 0, sizeof(resp));
    resp.type = UHID_INPUT2; 
    CTAPPacket frame = respond(report);
    std::vector<uint8_t> response = frame.stringify();
    memcpy(resp.u.input2.data, response.data(), response.size());
    resp.u.input2.size = response.size(); 
    return resp;
}

inline uhid_event make_response(CTAPPacket &packet) {
    struct uhid_event resp;
    memset(&resp, 0, sizeof(resp));
    resp.type = UHID_INPUT2; 
    std::vector<uint8_t> response = packet.stringify();
    memcpy(resp.u.input2.data, response.data(), response.size());
    resp.u.input2.size = response.size(); 
    return resp;   
}

#endif
