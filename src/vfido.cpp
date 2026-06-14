#include <stdio.h>
#include <stdint.h>

#include "device.hpp"
#include "event.hpp"
#include "credentials/credential.hpp"

extern FIDODevice device;
extern CredentialStore store;

int main() {
    device.init();
    printf("UHID device created\n"); 
    run(device);
    return 0;
}
