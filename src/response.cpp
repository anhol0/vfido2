#include <exception>
#include <iostream>
#include <cstdint>
#include <vector>
#include "response.hpp"
#include "cancellation.hpp"
#include "error.hpp"
#include "device.hpp"
#include "uhid_report.hpp"
#include "cbor_operations/cbor.hpp"
#include "registration/registration.hpp"
#include "authentication/authenticate.hpp"

// extern CredentialStore store;

constexpr uint8_t CAPABILITY_WINK = 0x01;
constexpr uint8_t CAPABILITY_CBOR = 0x04;
constexpr uint8_t CAPABILITY_NMSG = 0x08;

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
#ifdef DEBUG
    for(const auto &a : out) {
        // Adding initialization packet to the sequence
        printf("\x1b[1;32mOut data: \x1b[0m");
        for(const auto &b : a) {
             printf("%02x", b);
        }
        printf("\n");
    }
#endif
    return out;
}

void print_packet(std::string method, std::vector<uint8_t> &payload) {
    std::cout << "\x1b[1;33m" << method << " payload size is: " << payload.size() << "\n";
    std::cout << "Payload: ";
    for(int i = 0; i < payload.size(); i++) {
        printf("%02x", payload[i]);
    }
    std::cout << "\n\x1b[0m";
}
void print_response_payload(std::string method, std::vector<uint8_t> &payload) {
    std::cout << "\x1b[1;33m" << method << " response payload size is: " << payload.size() << "\n";
    std::cout << "Payload: ";
    for(int i = 0; i < payload.size(); i++) {
        printf("%02x", payload[i]);
    }
    std::cout << "\n\x1b[0m";
}

// std::optional<CTAPPacket> respond(UHIDReport &r) {
//     CTAPPacket packet;
//     switch(r.cmd) {
//         case CTAPHID_CBOR: {

//         }
//         case CTAPHID_MSG:
//         case CTAPHID_CANCEL:
//         case CTAPHID_PING:
//         case CTAPHID_WINK:
//         case CTAPHID_LOCK:
//         case CTAPHID_ERROR:
//             break;
//     }
//     return packet;
// }

CTAPPacket handle_init(UHIDReport &request, uint32_t assigned_cid) {
    CTAPPacket response;
    // --- INIT PAYLOAD STRUCTURE ---
    // Echoed Nonce (8 Bytes)
    // New Channel ID (4 bytes)
    // Protocol version identifier (1 Byte) (02)
    // Major device version number (1 Byte)
    // Minor device version number (i Byte)
    // Build number (1 Byte)
    // Capabilities (1 Byte)
    std::vector<uint8_t> payload;
    if(request.payload.size() != 8) {
        return make_hid_error(request.cid, HIDError::CTAP1_ERR_INVALID_LENGTH);
    }
    payload.insert(payload.end(), request.payload.begin(), request.payload.begin() + 8);
    payload.push_back((assigned_cid >> 24) & 0xFF);
    payload.push_back((assigned_cid >> 16) & 0xFF);
    payload.push_back((assigned_cid >>  8) & 0xFF);
    payload.push_back((assigned_cid >>  0) & 0xFF);

    payload.push_back(0x02);
    payload.push_back(0x01);
    payload.push_back(0x00);
    payload.push_back(0x00);

    uint8_t capabilities = CAPABILITY_CBOR | CAPABILITY_NMSG;
    payload.push_back(capabilities);

    response.cid = request.cid;
    response.cmd = CTAPHID_INIT | MASK;
    response.payload = std::move(payload);
    response.len = static_cast<uint16_t>(response.payload.size());
    return response;
}

CTAPPacket handle_ping(UHIDReport &request) {
    CTAPPacket response;
    response.cid = request.cid;
    response.cmd = CTAPHID_PING | MASK;
    response.payload = request.payload;
    response.len =
        static_cast<uint16_t>(response.payload.size());
    return response;
}

CTAPPacket handle_cbor(UHIDReport &request, std::stop_token stop) {
    CTAPPacket packet;
    const uint8_t command = request.payload[0];
    std::vector<uint8_t> payload;
    // Payload generation
    if(command == 0x04) {              // authenticatorGetInfo
        // CBOR
        auto cbor = build_getinfo_response();
        // Encoding JSON in CBOR
        payload.insert(payload.end(), cbor.begin(), cbor.end());
    }

    else if(command == 0x01) {       // authenticatorMakeCredential
        payload.insert(payload.end(), request.payload.begin() + 1, request.payload.end());

#ifdef DEBUG
        // Debugging payload reassembly
        print_packet("authenticatorMakeCredential", payload);
#endif
        // Parsing the request
        CTAPMakeCredentialRequest mcr;
        if(!mcr.parseRequest(payload)) {
            std::cerr << "There is a problem with the authenticatorMakeCredential request\n";
            return make_cbor_error(request.cid, CTAPError::CTAP2_ERR_INVALID_CBOR);
        }

        // Building the response
        try {
            payload = mcr.build_response(request, stop);
        } catch (const OperationCancelled&) {
            throw;
        } catch(std::exception &e) {
            std::cerr << "There is a problem with the authenticatorMakeCredential request: " << e.what() << "\n";
            return make_cbor_error(request.cid, CTAPError::CTAP1_ERR_OTHER);
        }

        // Returning error in case of single-byte payload
        // The byte is a CTAP error code
        if(payload.size() == 1) {
            std::cout << "Build single-byte payload\n";
            return make_cbor_error(request.cid, static_cast<CTAPError>(payload[0]));
        }
    }

    else if(command == 0x02 || command == 0x08) {          // authenticatorGetAssertion
        payload.insert(payload.end(), request.payload.begin() + 1, request.payload.end());

#ifdef DEBUG
        if(command == 0x02) {
            print_packet("authenticatorGetAssertion", payload);
        } else if(command == 0x08) {
            print_packet("authenticatorGetNextAssertion", payload);
        }
#endif

        // Parse the authenticatorGetAssertion request

        static CTAPGetAssertionRequest gar;
        if(command == 0x02) {
            gar.clear();
            if(!gar.parseRequest(payload)) {
                gar.clear();
                std::cerr << "There is a problem with the authenticatorGetAssertion request\n";
                return make_cbor_error(request.cid, CTAPError::CTAP2_ERR_INVALID_CBOR);
            }
            gar.set_origin_cid(request.cid);

            try {
                payload = gar.build_response(request, stop);
            } catch (const OperationCancelled&) {
                gar.clear();
                throw;
            } catch (const std::exception& e) {
                std::cerr << "Error building response: " << e.what() << "\n";
                gar.clear();
                return make_cbor_error(request.cid, CTAPError::CTAP1_ERR_OTHER);
            }
        } else if(command == 0x08) {
            if(gar.get_origin_cid() == 0 || gar.get_origin_cid() != request.cid) {
                return make_cbor_error(
                    request.cid,
                    CTAPError::CTAP2_ERR_NOT_ALLOWED
                );
            }

            try {
                payload = gar.build_response_next(stop);
            } catch (const OperationCancelled&) {
                throw;
            } catch (const std::exception &e) {
                std::cerr << "Error building next response: " << e.what() << "\n";
                return make_cbor_error(request.cid, CTAPError::CTAP1_ERR_OTHER);
            }
        }

        if(payload.size() == 1) {
            std::cout << "Build single-byte payload\n";
            return make_cbor_error(request.cid, static_cast<CTAPError>(payload[0]));
        }

#ifdef DEBUG
        // Print payload contents for debugging purposes
        if(command == 0x02) {
            print_response_payload("authenticatorGetAssertion", payload);
        } else if(command == 0x08) {
            print_response_payload("authenticatorGetNextAssertion", payload);
        }
#endif
    } else {
        return make_cbor_error(request.cid, CTAPError::CTAP2_ERR_INVALID_SUBCOMMAND);
    }
    packet.cid = request.cid;
    packet.cmd = CTAPHID_CBOR | MASK;
    packet.len = (uint16_t)payload.size();
    packet.payload = payload;
    return packet;
}

void start_worker(UHIDReport &request);
