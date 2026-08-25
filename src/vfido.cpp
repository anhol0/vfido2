#include <exception>
#include <stdexcept>
#include <stdio.h>
#include <stdint.h>

#include "cryptography/tpm.hpp"
#include "device.hpp"
#include "event.hpp"
#include "credentials/credential.hpp"
#include <nlohmann/detail/exceptions.hpp>
#include <iostream>
#include <system_error>

// Store is a global variable and not protected by a mutex, atomic or any synchronization object
// This is done intentionally. It can be accessed only by one thread at a time no matter what
// It is only utilized when getAssertion and makeCredential requests are sent.
// There can't be multiple concurrent operations of this type by the specification of CTAPHID protocol
// It is totally safe to leave it as is
CredentialStore store{
    "/etc/vfido2/cred.bin",
    get_or_create_store_key()
};

int main() {
    // Device can be local since it is only used in the main event loop
    // Only run() method is responsible for dealing with FIDODevice
    FIDODevice device;
    try {
        device.init();
        store.load();
    } catch (nlohmann::detail::parse_error &e) {
        std::cout << "Credential storage parsing error: " << e.what() << std::endl;
        return 1;
    } catch (nlohmann::json::type_error &e) {
        std::cout << "Credential Map validation error: " << e.what() << std::endl;
        return 1;
    } catch (nlohmann::json::exception &e) {
        std::cout << "Exception for JSON: " << e.what() << std::endl;
        return 1;
    } catch (std::system_error &e) {
        std::cout << "System error occured: " << e.what() << "[Code " << e.code() << "]" << std::endl;
        return 1;
    } catch (std::runtime_error &e) {
        std::cout << "Credential Map valication error: " << e.what() << std::endl;
        return 1;
    } catch (std::invalid_argument &e){
        std::cout << "Conversion error: " << e.what() << std::endl;
        return 1;
    } catch (std::out_of_range &e) {
        std::cout << "Conversion out of range: " << e.what() << std::endl;
        return 1;
    } catch (std::exception &e) {
        std::cout << "Other exception is caught: " << e.what() << std::endl;
        return 1;
    }
    printf("UHID device created\n");
    run(device);
    return 0;
}
