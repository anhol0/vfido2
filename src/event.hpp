#pragma once

#include "credentials/credential.hpp"
#include "device.hpp"

class CredentialKeyProvider;
class UserInteraction;

void run(
    FIDODevice& device,
    CredentialStore& store,
    CredentialKeyProvider& key_provider,
    UserInteraction& user_interaction
);
