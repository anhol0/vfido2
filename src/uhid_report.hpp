#ifndef UHID_REPORT_HPP
#define UHID_REPORT_HPP

#include <cstdint>
#include <vector>

#define MAX_INIT_PAYLOAD_SIZE 57 // 64 - 4 - 1 - 2
#define MAX_CONT_PAYLOAD_SIZE 59 // 64 - 4 - 1                                 
#define MAX_RESP_PAYLOAD_SIZE 

class UHIDReport {
public:
    uint32_t cid; 
    uint8_t cmd;
    uint16_t len;
    std::vector<uint8_t> payload;
    bool is_init_frame;
    uint8_t seq = 0;
    void clear();
};

inline void UHIDReport::clear() {
    payload.clear();
}

#endif
