#pragma once

#include "credentials/credential.hpp"
#include "device.hpp"

class CredentialKeyProvider;

void run(
    FIDODevice& device,
    CredentialStore& store,
    CredentialKeyProvider& key_provider
);
