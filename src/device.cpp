#include "device.hpp"
#include <linux/uhid.h>
#include <stdexcept>

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
