#ifndef DEVICE_HPP
#define DEVICE_HPP

#include "error.hpp"
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

class FIDODevice {
public:
    FIDODevice();
    ~FIDODevice();
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

std::vector<uhid_event> make_response(UHIDReport &report); 
std::vector<uhid_event> make_response(CTAPPacket &packet);
CTAPPacket make_err(CTAPError err, uint32_t cid);

#endif
