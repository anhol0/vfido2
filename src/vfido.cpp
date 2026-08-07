#include <stdio.h>
#include <stdint.h>

#include "device.hpp"
#include "event.hpp"
#include "credentials/credential.hpp"

// Store is a global variable and not protected by a mutex, atomic or any synchronization object
// This is done intentionally. It can be accessed only by one thread at a time no matter what
// It is only utilized when getAssertion and makeCredential requests are sent.
// There can't be multiple concurrent operations of this type by the specification of CTAPHID protocol
// It is totally safe to leave it as is
CredentialStore store;

int main() {
    // Device can be local since it is only used in the main event loop
    // Only run() method is responsible for dealing with FIDODevice
    FIDODevice device;
    device.init();
    store.init();
    printf("UHID device created\n");
    run(device);
    return 0;
}
