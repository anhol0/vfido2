#ifndef EVENT_HPP
#define EVENT_HPP

#include "credential.hpp"
#include "device.hpp"

static CredentialStore store;
static FIDODevice device;

void run(FIDODevice &device);

#endif 
