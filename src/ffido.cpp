// MIT License
// 
// Copyright (c) 2026 Efim Belorusets
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <cmath>
#include <cstdint>
#include <iostream>
#include <linux/uhid.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <stdint.h>

#include "device.hpp"
#include "response.hpp"
#include "uhid_report.hpp"
#include "macro.hpp"

// --- REQUEST STRUCTURE ---
// Channel ID (4 Bytes)
// CMD (1 Byte)
// Payload length (2 Bytes)
// Nonce (randomly generated, N Bytes)
// Padding (0 everything until 64 bytes)

// --- RESPONSE STRUCTURE ---
// Same report id (1 Byte)
// Same broadcast channel (4 Bytes) 
// Response CMD (1 Byte)
// Payload length (2 Bytes)
// Payload (N Bytes)
// Padding (zero everything until size of 64 bytes)

// -- Payload example for INIT--
// Echoed Nonce (8 Bytes) 
// New Channel ID (4 bytes) 
// Protocol version identifier (1 Byte) (02)
// Major device version number (1 Byte) 
// Minor device version number (i Byte) 
// Build number (1 Byte)
// Capabilities (1 Byte)

static const uint8_t fido_report_desc[] = {
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
};

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
            uint8_t is_init_fragment = (data[5] & 0x80);
            bool respd = false;

            if(is_init_fragment) {
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
