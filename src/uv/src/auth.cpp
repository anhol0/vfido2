#include "auth.hpp"

#include "auth_handler.hpp"
#include "cancellable_process.hpp"
#include "cancellation.hpp"
#include "keepalive.hpp"

#include <chrono>
#include <security/_pam_types.h>
#include <stdexcept>
#include <string>
#include <system_error>
#include <termios.h>
#include <unistd.h>

namespace {

constexpr auto USER_ACTION_TIMEOUT = std::chrono::seconds(30);

class TerminalStateRestorer {
public:
    TerminalStateRestorer() noexcept {
        valid_ = tcgetattr(STDIN_FILENO, &original_) == 0;
    }

    ~TerminalStateRestorer() {
        if(valid_)
            static_cast<void>(tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_));
    }

    TerminalStateRestorer(const TerminalStateRestorer&) = delete;
    TerminalStateRestorer& operator=(const TerminalStateRestorer&) = delete;

private:
    termios original_{};
    bool valid_ = false;
};

std::string zenity_program() {
    constexpr const char* candidates[] = {
        "/usr/bin/zenity",
        "/bin/zenity"
    };
    for(const char* candidate : candidates) {
        if(access(candidate, X_OK) == 0)
            return candidate;
    }
    throw std::runtime_error("zenity executable was not found");
}

}

int authenticate_user(
    const std::string& username,
    const std::string& process_name,
    const std::string& confdir,
    std::stop_token stop,
    KeepaliveState& keepalive
) {
    // The handler normally restores echo itself. This guard also restores the
    // daemon's original terminal state if cancellation requires SIGKILL.
    TerminalStateRestorer terminal;
    UserActionKeepaliveGuard waiting_for_user(keepalive);
    const int status = vfido::uv::run_cancellable_program(
        "/proc/self/exe",
        {
            std::string(VFIDO_AUTH_HANDLER_COMMAND),
            username,
            process_name,
            confdir
        },
        stop,
        USER_ACTION_TIMEOUT
    );
    if(status < PAM_SUCCESS || status > PAM_INCOMPLETE)
        return PAM_SYSTEM_ERR;
    return status;
}

bool collect_consent(
    const std::string& question,
    std::stop_token stop,
    KeepaliveState& keepalive
) {
    try {
        const std::string program = zenity_program();
        UserActionKeepaliveGuard waiting_for_user(keepalive);
        return vfido::uv::run_cancellable_program(
            program,
            {"--question", "--text=" + question},
            stop,
            USER_ACTION_TIMEOUT
        ) == 0;
    } catch(const OperationCancelled&) {
        throw;
    } catch(const UserActionTimedOut&) {
        throw;
    } catch(const std::exception&) {
        return false;
    }
}

std::string get_user_name() {
    const char* name = getlogin();
    if(name == nullptr)
        throw std::runtime_error("Unable to get current user name");
    return name;
}
