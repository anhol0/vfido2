#include "secret_pipe.hpp"

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <stdexcept>
#include <system_error>
#include <sys/stat.h>
#include <unistd.h>

namespace vauth::dbus {

vauth::uv::SensitiveBytes read_secret_pipe(int fd) {
    if(fd < 0)
        throw std::invalid_argument("Password pipe descriptor is invalid");

    struct stat status{};
    if(fstat(fd, &status) != 0) {
        throw std::system_error(
            errno,
            std::generic_category(),
            "inspect password pipe"
        );
    }
    if(!S_ISFIFO(status.st_mode))
        throw std::invalid_argument("Password descriptor is not a pipe");

    const int flags = fcntl(fd, F_GETFL);
    if(flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        throw std::system_error(
            errno,
            std::generic_category(),
            "make password pipe nonblocking"
        );
    }

    vauth::uv::SensitiveBytes password(vauth::uv::MAX_PASSWORD_SIZE + 1);
    std::size_t used = 0;
    while(true) {
        auto storage = password.writable_bytes();
        const ssize_t count = read(
            fd,
            storage.data() + used,
            storage.size() - used
        );
        if(count > 0) {
            used += static_cast<std::size_t>(count);
            if(used > vauth::uv::MAX_PASSWORD_SIZE)
                throw std::invalid_argument("Password is too long");
            continue;
        }
        if(count == 0)
            break;
        if(errno == EINTR)
            continue;
        if(errno == EAGAIN || errno == EWOULDBLOCK) {
            throw std::invalid_argument(
                "Password pipe must be closed before submission"
            );
        }
        throw std::system_error(
            errno,
            std::generic_category(),
            "read password pipe"
        );
    }

    password.resize(used);
    if(std::ranges::find(password.bytes(), uint8_t{0}) != password.bytes().end())
        throw std::invalid_argument("Password contains a NUL byte");
    return password;
}

}
