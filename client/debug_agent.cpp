#include "dbus/constants.hpp"

#include <sdbus-c++/sdbus-c++.h>

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

std::string display_message(
    const std::string& state,
    const std::string& operation,
    const std::string& relying_party_id
) {
    const std::string target = relying_party_id.empty()
        ? std::string{}
        : " for " + relying_party_id;
    if(state == "presence_required")
        return "User presence required" + target;
    if(state == "presence_approved")
        return "User presence approved" + target;
    if(state == "presence_denied")
        return "User presence denied" + target;
    if(state == "verification_started")
        return "User verification started" + target;
    if(state == "fingerprint_required")
        return "Touch the fingerprint reader" + target;
    if(state == "fingerprint_failed")
        return "Fingerprint was not recognized" + target;
    if(state == "password_required")
        return "Password is required" + target;
    if(state == "verification_succeeded")
        return "User verification succeeded" + target;
    if(state == "verification_failed")
        return "User verification failed" + target;
    if(state == "cancelled")
        return "Operation was cancelled" + target;
    if(state == "timed_out")
        return "Operation timed out" + target;
    return "State " + state + " during " + operation + target;
}

}

int main() {
    try {
        auto connection = sdbus::createSystemBusConnection();
        auto proxy = sdbus::createProxy(
            *connection,
            sdbus::ServiceName{std::string(vauth::dbus::SERVICE_NAME)},
            sdbus::ObjectPath{std::string(vauth::dbus::OBJECT_PATH)}
        );

        uint64_t generation = 0;
        auto state_slot = proxy->uponSignal(
            std::string(vauth::dbus::STATE_SIGNAL)
        ).onInterface(
            std::string(vauth::dbus::INTERFACE_NAME)
        ).call(
            [&generation](
                uint64_t signal_generation,
                const std::string& state,
                const std::string& operation,
                const std::string& relying_party_id
            ) {
                if(signal_generation != generation)
                    return;
                std::cout << "D-Bus state: " << state << " ("
                          << operation << ")\n"
                          << display_message(
                              state,
                              operation,
                              relying_party_id
                          ) << '\n';
            },
            sdbus::return_slot
        );

        proxy->callMethod(
            std::string(vauth::dbus::REGISTER_METHOD)
        ).onInterface(
            std::string(vauth::dbus::INTERFACE_NAME)
        ).storeResultsTo(generation);

        if(generation == 0)
            throw std::runtime_error("Daemon returned an invalid generation");
        std::cout << "Registered vAuth UI agent generation "
                  << generation << "\n";
        connection->enterEventLoop();
        return 0;
    } catch(const std::exception& error) {
        std::cerr << "vauth-agent-debug: " << error.what() << '\n';
        return 1;
    }
}
