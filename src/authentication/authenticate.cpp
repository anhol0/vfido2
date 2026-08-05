#include "authenticate.hpp"

bool CTAPGetAsserionRequest::parseRequest(std::vector<uint8_t> &payload)
{
    return false;
}

std::vector<uint8_t> CTAPGetAsserionRequest::build_response(UHIDReport &r)
{
    return std::vector<uint8_t>();
}