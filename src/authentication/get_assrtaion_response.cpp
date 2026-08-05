#include "authenticate.hpp"

extern StoredCredential store;

std::vector<uint8_t> CTAPGetAssertionRequest::build_response(UHIDReport &r)
{
    if(allowList.size() != 0) {
        // Get all the credentials bound to a cpecific rpId
    }
}