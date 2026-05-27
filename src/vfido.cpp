#include <stdio.h>
#include <stdint.h>

#include "device.hpp"
#include "event.hpp"

int main() {
    device.init();
    printf("UHID device created\n"); 
    run(device);
    return 0;
}
