#include <cstdint>
#include <iostream>
#include <stdio.h>
#include <stdint.h>

#include "device.hpp"
#include "response.hpp"
#include "uhid_report.hpp"
#include "macro.hpp"

// --- HEADER STRUCTURE ---
// Channel ID (4 Bytes)
// CMD (1 Byte)
// Payload length (2 Bytes)
// Payload (N Bytes)
// Padding (zero everything until 64 bytes)

int main() {
    FIDODevice device;
    device.init();
    printf("UHID device created\n");
    UHIDReport report;

    while (1) {
        if(!device.get()) {
            continue;
        }

        // If input from the browser 
        if (device.get_type() == UHID_OUTPUT) {

            printf("\x1b[1;31mGot data: \x1b[0m");
            std::vector<uint8_t> data = device.get_data();
            for(int i = 1; i < data.size(); i++) {
                printf("%02x", data[i]);
            }
            std::cout << "\n";


            // Check if the frame is initialization frame
            uint8_t is_init_packet = (data[5] & 0x80);
            bool respd = false;

            if(is_init_packet) {
                // Channel ID (4 bytes)
                uint32_t cid = ((uint32_t)data[1] << 24) |
                               ((uint32_t)data[2] << 16) |
                               ((uint32_t)data[3] << 8 ) |
                               ((uint32_t)data[4]);
                // Command (1 byte) 
                uint8_t cmd = data[5] & 0x7F;
                // Length of the nonce (2 bytes)
                uint16_t length = MAKE_U16(data[6], data[7]); 

                report.cid = cid;
                report.cmd = cmd;
                report.len = length;

                // If it is initialization packet and payload is bigger then MAX_INIT_PAYLOAD_SIZE
                if(report.len > MAX_INIT_PAYLOAD_SIZE) {
                    for(int i = 0; i < MAX_INIT_PAYLOAD_SIZE; i++) {
                        report.payload.push_back(data[8+i]);
                    }
                    respd = false;
                } 
                // If init packet is the only one in the packet sequence
                else {
                    for(int i = 0; i < report.len; i++) {
                        report.payload.push_back(data[8+i]); 
                    }
                    respd = true;
                }             
            } else {
                uint8_t expected_seq = report.seq;
                report.seq = data[5]; 
                if(expected_seq != report.seq) {
                    std::cerr << "Continuation packets out of order\n";
                    CTAPPacket err_p;
                    err_p.cmd = CTAPHID_ERROR;
                    err_p.len = 1;
                    err_p.cid = report.cid;
                    err_p.payload.push_back(ERR_INVALID_SEQ);
                    err_p.stringify();
                    // Sendind err response
                    struct uhid_event resp = make_response(err_p);
                    device.send(resp);
                    report.clear();
                    continue;
                }
                report.seq++;
                // If continuation packet 
                for(int i = 0; i < MAX_CONT_PAYLOAD_SIZE; i++) {
                    report.payload.push_back(data[6+i]);                    
                    // If size of payload recieved = size of payload expected
                    // Break tf out
                    if(report.payload.size() >= report.len) {
                        respd = true;
                        break;
                    }
                }
            }

            if(respd) {
                // Respond based on the CMD
                struct uhid_event resp = make_response(report);
                device.send(resp);
                report.clear();
            }
        }
    }

    return 0;
}
