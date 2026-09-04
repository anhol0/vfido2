#pragma once

#include <string_view>

namespace vauth::dbus {

inline constexpr std::string_view SERVICE_NAME = "org.lamellix.vAuth";
inline constexpr std::string_view OBJECT_PATH = "/org/lamellix/vAuth";
inline constexpr std::string_view INTERFACE_NAME =
    "org.lamellix.vAuth.UserInteraction1";
inline constexpr std::string_view REGISTER_METHOD = "RegisterAgent";
inline constexpr std::string_view UNREGISTER_METHOD = "UnregisterAgent";
inline constexpr std::string_view RESPOND_TO_PRESENCE_METHOD =
    "RespondToPresence";
inline constexpr std::string_view SUBMIT_PASSWORD_METHOD = "SubmitPassword";
inline constexpr std::string_view CANCEL_INTERACTION_METHOD =
    "CancelInteraction";
inline constexpr std::string_view STATE_SIGNAL = "StateChanged";

}
