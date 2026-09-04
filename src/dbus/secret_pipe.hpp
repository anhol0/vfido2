#pragma once

#include "uv/src/sensitive_bytes.hpp"

namespace vauth::dbus {

[[nodiscard]] vauth::uv::SensitiveBytes read_secret_pipe(int fd);

}
