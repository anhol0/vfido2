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

void respond_to_presence(
    sdbus::IProxy& proxy,
    uint64_t generation,
    uint64_t request_id
) {
    std::cout << "Allow this operation? [y/N/cancel] " << std::flush;
    std::string response;
    if(!std::getline(std::cin, response))
        response.clear();

    if(response == "c" || response == "cancel") {
        proxy.callMethod(
            std::string(vauth::dbus::CANCEL_INTERACTION_METHOD)
        ).onInterface(
            std::string(vauth::dbus::INTERFACE_NAME)
        ).withArguments(generation, request_id);
        return;
    }

    const bool approved = response == "y" || response == "yes";
    proxy.callMethod(
        std::string(vauth::dbus::RESPOND_TO_PRESENCE_METHOD)
    ).onInterface(
        std::string(vauth::dbus::INTERFACE_NAME)
    ).withArguments(generation, request_id, approved);
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
            [&generation, proxy = proxy.get()](
                uint64_t signal_generation,
                uint64_t request_id,
                const std::string& state,
                const std::string& operation,
                const std::string& relying_party_id
            ) {
                if(signal_generation != generation)
                    return;
                std::cout << "D-Bus state: " << state
                          << " [request " << request_id << "] ("
                          << operation << ")\n"
                          << display_message(
                              state,
                              operation,
                              relying_party_id
                          ) << '\n';
                if(state == "presence_required") {
                    try {
                        respond_to_presence(
                            *proxy,
                            generation,
                            request_id
                        );
                    } catch(const std::exception& error) {
                        std::cerr << "Presence response failed: "
                                  << error.what() << '\n';
                    }
                }
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
