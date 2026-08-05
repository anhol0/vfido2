#include <cstdint>
#include <openssl/obj_mac.h>
#include <sys/types.h>
#include <vector>
#include <openssl/rand.h>
#include <openssl/ec.h>

#include "credential.hpp"
#include "error.hpp"
#include "event.hpp"
#include "registration.hpp"
#include "crypto.hpp"
#include "const.hpp"
#include "uhid_report.hpp"

void CTAPMakeCredentialRequest::build_response(UHIDReport &r) {

    if(excludeList.size() > 0) {
        for(const auto &d : excludeList) {
            if(store.has(d.id)) {
                device.send_err(CTAPError::CTAP2_ERR_CREDENTIAL_EXCLUDED, r.cid);
                return;   
            }
        }
    }

    // Building CBOR map of:
    // rpIdHash
    std::vector<uint8_t> rphash = sha256(rp.id);

    // Flags 
    uint8_t flags = 0x00;
    flags |= (uint8_t)options["up"] << 0;
    flags |= (uint8_t)options["uv"] << 2;
    flags |= 1 << 6;
    int sc = signCounter++;

    // Building Attested Credential data
    std::vector<uint8_t> authData;
    std::vector<uint8_t> credId(32);
    RAND_bytes(credId.data(), credId.size());
    uint16_t credIdLen = (uint16_t)credId.size();
    uint8_t credIdLenBytes[2] = {
        (uint8_t)(credIdLen >> 8),
        (uint8_t)(credIdLen >> 0)
    };

    authData.insert(authData.end(), aaguid.begin(), aaguid.begin() + 16);
    authData.insert(authData.end(), credId.begin(), credId.end());
    authData.push_back(credIdLenBytes[0]);
    authData.push_back(credIdLenBytes[1]);
    authData.insert(authData.end(), credId.begin(), credId.end());
}
