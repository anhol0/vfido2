#ifndef DEVICE_HPP
#define DEVICE_HPP

#include "uhid_report.hpp"
#include "response.hpp"
#include <array>
#include <cstdint>
#include <cstdio>
#include <linux/uhid.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <cerrno>
#include <unistd.h>
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
    int fd;
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


std::vector<uhid_event> make_response(UHIDReport &report); 
std::vector<uhid_event> make_response(CTAPPacket &packet);

#endif
