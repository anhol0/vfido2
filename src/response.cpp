#include <iostream>
#include <cstdint>
#include "response.hpp"
#include "error.hpp"
#include "credentials/credential.hpp"
#include "device.hpp"
#include "uhid_report.hpp"
#include "cbor_operations/cbor.hpp"
#include "registration/registration.hpp"
#include "authentication/authenticate.hpp"

extern CredentialStore store;

uint32_t gen_cid() {
    uint32_t cid;
    do {
        arc4random_buf(&cid, sizeof(cid));
    } while (cid == 0xffffffff);
    return cid;
}

std::vector<std::vector<uint8_t>> CTAPPacket::stringify() {
    std::vector<std::vector<uint8_t>> out;
    std::vector<uint8_t> out_v;
    std::vector<uint8_t> channel_id;
    channel_id.push_back(cid >> 24 & 0xFF);
    channel_id.push_back(cid >> 16 & 0xFF);
    channel_id.push_back(cid >>  8 & 0xFF);
    channel_id.push_back(cid >>  0 & 0xFF);
    // Building initialization packet header
    out_v.insert(out_v.end(), channel_id.begin(), channel_id.end());
    out_v.push_back(cmd);
    out_v.push_back(len >> 8 & 0xFF);
    out_v.push_back(len >> 0 & 0xFF);
    int i = 0;
    while(out_v.size() < 64) {
        if(i < payload.size()) {
            out_v.push_back(payload[i]);
        } else
            out_v.push_back(0x00);
        i++;
    }
    out.push_back(out_v);
    if(i < payload.size()) {
        uint8_t sequence = 0;
        while(i < payload.size()) {
            std::vector<uint8_t> v;
            v.insert(v.end(), channel_id.begin(), channel_id.end());
            v.push_back(sequence);
            while(v.size() < 64) {
                if(i < payload.size()) {
                    v.push_back(payload[i++]);
                } else {
                    v.push_back(0x00);
                }
            }
            out.push_back(v);
            sequence++;
        }
    }
    for(const auto &a : out) {
        // Adding initialization packet to the sequence
        printf("\x1b[1;32mOut data: \x1b[0m");
        for(const auto &b : a) {
             printf("%02x", b);
        }
        printf("\n");
    }
    return out;
}

std::optional<CTAPPacket> respond(UHIDReport &r) {
    CTAPPacket packet;
    switch(r.cmd) {
        case CTAPHID_INIT: {
            // --- INIT PAYLOAD STRUCTURE ---
            // Echoed Nonce (8 Bytes)
            // New Channel ID (4 bytes)
            // Protocol version identifier (1 Byte) (02)
            // Major device version number (1 Byte)
            // Minor device version number (i Byte)
            // Build number (1 Byte)
            // Capabilities (1 Byte)
            uint32_t new_cid = gen_cid();
            std::vector<uint8_t> payload;
            if(r.payload.size() < 8) {
                std::perror("Broken INIT packet arrived");
                break;
            }
            payload.insert(payload.end(), r.payload.begin(), r.payload.begin() + 8);
            payload.push_back((new_cid >> 24) & 0xFF);
            payload.push_back((new_cid >> 16) & 0xFF);
            payload.push_back((new_cid >>  8) & 0xFF);
            payload.push_back((new_cid >>  0) & 0xFF);
            payload.push_back(0x02);
            payload.push_back(0x01);
            payload.push_back(0x00);
            payload.push_back(0x00);
            payload.push_back(0x05);
            packet.cid = 0xffffffff;
            packet.cmd = CTAPHID_INIT | MASK;
            packet.len = (uint16_t)payload.size();
            packet.payload = payload;
            break;
        }
        case CTAPHID_CBOR: {
            std::vector<uint8_t> payload;
            // Payload generation
            if(r.payload[0] == 0x04) {              // authenticatorGetInfo
                // CBOR
                auto cbor = build_getinfo_response();
                // Encoding JSON in CBOR
                payload.insert(payload.end(), cbor.begin(), cbor.end());
            }

            else if(r.payload[0] == 0x01) {       // authenticatorMakeCredential
                payload.insert(payload.end(), r.payload.begin() + 1, r.payload.end());

                // Debugging payload reassembly
                printf("\x1b[1;33mauthenticatorMakeCredential payload size is: %lu\n", payload.size());
                printf("Payload: ");
                for(int i = 0; i < payload.size(); i++) {
                    printf("%02x", payload[i]);
                }
                printf("\n\x1b[0m");
                //

                // Parsing the request
                CTAPMakeCredentialRequest mcr;
                if(!mcr.parseRequest(payload)) {
                    std::cerr << "There is a problem with the authenticatorMakeCredential request\n";
                    return make_err(CTAPError::CTAP2_ERR_INVALID_CBOR, r.cid);
                }

                // Idk how to handle when packet arrives with make.me.blink Relying Party ID
                // Returning empty response to avoid further processing
                if(mcr.rp.id == "make.me.blink") {
                    return {};
                }

                // Building the response
                try {
                    payload = mcr.build_response(r);
                } catch(std::exception &e) {
                    std::cerr << "There is a problem with the authenticatorMakeCredential request: " << e.what() << "\n";
                    return make_err(CTAPError::CTAP2_ERR_INVALID_CBOR, r.cid);
                }

                // Returning error in case of single-byte payload
                // The byte is a CTAP error code
                if(payload.size() == 1) {
                    std::cout << "Build single-byte payload\n";
                    return make_err(static_cast<CTAPError>(payload[0]), r.cid);
                }
            }

            else if(r.payload[0] == 0x02) {          // authenticatorGetAssertion
                std::cout << "Got authenticatorGetAssertion command\n";
                payload.insert(payload.end(), r.payload.begin() + 1, r.payload.end());

                // Print payload contents for debugging purposes
                printf("\x1b[1;33mauthenticatorGetAssertion payload size is: %lu\n", payload.size());
                printf("Payload: ");
                for(int i = 0; i < payload.size(); i++) {
                    printf("%02x", payload[i]);
                }
                printf("\n\x1b[0m");

                // Parse the authenticatorGetAssertion request
                CTAPGetAssertionRequest gar;
                if(!gar.parseRequest(payload)) {
                    std::cerr << "There is a problem with the authenticatorGetAssertion request\n";
                    return make_err(CTAPError::CTAP2_ERR_INVALID_CBOR, r.cid);
                }

                try {
                    payload = gar.build_response(r);
                } catch (const std::exception& e) {
                    std::cerr << "Error building response: " << e.what() << "\n";
                    return make_err(CTAPError::CTAP2_ERR_INVALID_CBOR, r.cid);
                }

                // For now working on the logic to handle the request
                // so returning that there are no credentials
                return make_err(CTAPError::CTAP2_ERR_NO_CREDENTIALS, r.cid);

            }
            packet.cid = r.cid;
            packet.cmd = CTAPHID_CBOR | MASK;
            packet.len = (uint16_t)payload.size();
            packet.payload = payload;
            break;
        }
        case CTAPHID_MSG:
        case CTAPHID_CANCEL:
        case CTAPHID_PING:
        case CTAPHID_WINK:
        case CTAPHID_LOCK:
        case CTAPHID_ERROR:
            break;
    }
    return packet;
}
