#include <exception>
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

constexpr uint8_t CAPABILITY_WINK = 0x01;
constexpr uint8_t CAPABILITY_CBOR = 0x04;
constexpr uint8_t CAPABILITY_NMSG = 0x08;

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
    return out;
}

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

CTAPPacket handle_cbor(
    UHIDReport& request,
    std::stop_token stop,
    CredentialStore& store,
    CredentialKeyProvider& key_provider,
    KeepaliveState& keepalive
) {
    CTAPPacket packet;
    const uint8_t command = request.payload[0];
    std::vector<uint8_t> payload;
    static CTAPGetAssertionRequest gar;
    if(command != 0x02 && command != 0x08) {
        gar.clear();
    }
    // Payload generation
    if(command == 0x04) {              // authenticatorGetInfo
        // CBOR
        auto cbor = build_getinfo_response();
        // Encoding JSON in CBOR
        payload.insert(payload.end(), cbor.begin(), cbor.end());
    }

    else if(command == 0x01) {       // authenticatorMakeCredential
        payload.insert(payload.end(), request.payload.begin() + 1, request.payload.end());

        // Parsing the request
        CTAPMakeCredentialRequest mcr;
        if(!mcr.parseRequest(payload)) {
            return make_cbor_error(request.cid, CTAPError::CTAP2_ERR_INVALID_CBOR);
        }

        // Building the response
        try {
            payload = mcr.build_response(
                request, stop, store, key_provider, keepalive
            );
        } catch (const OperationCancelled&) {
            throw;
        } catch (const UserActionTimedOut&) {
            throw;
        } catch(const std::exception&) {
            return make_cbor_error(request.cid, CTAPError::CTAP1_ERR_OTHER);
        }

        // Returning error in case of single-byte payload
        // The byte is a CTAP error code
        if(payload.size() == 1) {
            return make_cbor_error(request.cid, static_cast<CTAPError>(payload[0]));
        }
    }

    else if(command == 0x02 || command == 0x08) {          // authenticatorGetAssertion
        payload.insert(payload.end(), request.payload.begin() + 1, request.payload.end());

        if(command == 0x02) {
            // Since gar is static for caching purposes (see authenticatorGetNextAssertion),
            // It needs to be wiped before next authenticatorGetAssertion request can be processed
            gar.clear();
            // Parse the authenticatorGetAssertion request
            if(!gar.parseRequest(payload)) {
                gar.clear();
                return make_cbor_error(request.cid, CTAPError::CTAP2_ERR_INVALID_CBOR);
            }
            if(gar.has_rk_option()) {
                gar.clear();
                return make_cbor_error(
                    request.cid,
                    CTAPError::CTAP2_ERR_UNSUPPORTED_OPTION
                );
            }
            try {
                payload = gar.build_response(
                    request, stop, store, key_provider, keepalive
                );
            } catch (const OperationCancelled&) {
                gar.clear();
                throw;
            } catch (const UserActionTimedOut&) {
                gar.clear();
                throw;
            } catch (const std::exception&) {
                gar.clear();
                return make_cbor_error(request.cid, CTAPError::CTAP1_ERR_OTHER);
            }
        } else if(command == 0x08) {
            if(gar.get_origin_cid() == 0 || gar.get_origin_cid() != request.cid) {
                // Filtering out authenticatorGetNextAssertion packets
                // Packets with corrupted cid or cid that differs from origininal one are discarded
                return make_cbor_error(
                    request.cid,
                    CTAPError::CTAP2_ERR_NOT_ALLOWED
                );
            }

            try {
                payload = gar.build_response_next(
                    request.cid, stop, store, key_provider
                );
            } catch (const OperationCancelled&) {
                gar.clear();
                throw;
            } catch (const UserActionTimedOut&) {
                gar.clear();
                throw;
            } catch (const std::exception&) {
                gar.clear();
                return make_cbor_error(request.cid, CTAPError::CTAP1_ERR_OTHER);
            }
        }

        if(payload.size() == 1) {
            gar.clear();
            return make_cbor_error(request.cid, static_cast<CTAPError>(payload[0]));
        }
    } else {
        return make_cbor_error(request.cid, CTAPError::CTAP1_ERR_INVALID_COMMAND);
    }
    packet.cid = request.cid;
    packet.cmd = CTAPHID_CBOR | MASK;
    packet.len = (uint16_t)payload.size();
    packet.payload = payload;
    return packet;
}
