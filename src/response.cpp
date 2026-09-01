#include <exception>
#include <cstdint>
#include <utility>
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

namespace {

CTAPError encoding_error_to_ctap(const CborEncodingError& error) noexcept {
    return error.failure() == CborEncodingFailure::resource_limit
        ? CTAPError::CTAP2_ERR_REQUEST_TOO_LARGE
        : CTAPError::CTAP1_ERR_OTHER;
}

} // namespace

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
        try {
            payload = build_getinfo_response();
        } catch(const CborEncodingError& error) {
            return make_cbor_error(
                request.cid,
                encoding_error_to_ctap(error)
            );
        }
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
        } catch(const CborEncodingError& error) {
            return make_cbor_error(
                request.cid,
                encoding_error_to_ctap(error)
            );
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
            } catch(const CborEncodingError& error) {
                gar.clear();
                return make_cbor_error(
                    request.cid,
                    encoding_error_to_ctap(error)
                );
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
            } catch(const CborEncodingError& error) {
                gar.clear();
                return make_cbor_error(
                    request.cid,
                    encoding_error_to_ctap(error)
                );
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
    if(payload.size() > CTAPHID_MAX_PAYLOAD_SIZE) {
        return make_cbor_error(
            request.cid,
            CTAPError::CTAP2_ERR_REQUEST_TOO_LARGE
        );
    }
    packet.len = static_cast<uint16_t>(payload.size());
    packet.payload = std::move(payload);
    return packet;
}
