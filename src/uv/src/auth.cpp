#include "auth.hpp"

#include "auth_handler.hpp"
#include "cancellable_process.hpp"
#include "cancellation.hpp"
#include "keepalive.hpp"

#include <chrono>
#include <cerrno>
#include <limits>
#include <pwd.h>
#include <security/_pam_types.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <termios.h>
#include <unistd.h>
#include <utility>
#include <vector>

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
    const int status = vauth::uv::run_cancellable_program(
        "/proc/self/exe",
        {
            std::string(VAUTH_AUTH_HANDLER_COMMAND),
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

std::string_view presence_question(UserInteractionOperation operation) {
    switch(operation) {
        case UserInteractionOperation::make_credential:
            return "Authorize passkey creation?";
        case UserInteractionOperation::get_assertion:
            return "Authorize passkey usage?";
        case UserInteractionOperation::check_excluded_credential:
            return "Confirm user presence to continue passkey registration?";
    }
    return "Authorize passkey operation?";
}

bool collect_consent(
    std::string_view question,
    std::stop_token stop,
    KeepaliveState& keepalive
) {
    try {
        const std::string program = zenity_program();
        UserActionKeepaliveGuard waiting_for_user(keepalive);
        return vauth::uv::run_cancellable_program(
            program,
            {"--question", "--text=" + std::string(question)},
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

UserIdentity get_local_user_identity() {
    const char* name = getlogin();
    if(name == nullptr)
        throw std::runtime_error("Unable to get current user name");

    const std::string username(name);
    long buffer_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    if(buffer_size < 0)
        buffer_size = 16384;

    std::vector<char> buffer(static_cast<std::size_t>(buffer_size));
    passwd account{};
    passwd* result = nullptr;
    const int rc = getpwnam_r(
        username.c_str(),
        &account,
        buffer.data(),
        buffer.size(),
        &result
    );
    if(rc != 0)
        throw std::system_error(rc, std::generic_category(), "getpwnam_r");
    if(result == nullptr)
        throw std::runtime_error("Unable to resolve current user name");
    if(
        static_cast<uintmax_t>(account.pw_uid) >
        std::numeric_limits<uint32_t>::max()
    ) {
        throw std::runtime_error("Current user UID is out of range");
    }

    return UserIdentity{
        .uid = static_cast<uint32_t>(account.pw_uid),
        .name = username
    };
}

}

PamUserInteraction::PamUserInteraction(
    std::string process_name,
    std::string configuration_directory
) :
    processName_(std::move(process_name)),
    configurationDirectory_(std::move(configuration_directory))
{}

UserIdentity PamUserInteraction::current_user(std::stop_token stop) {
    cancellation_point(stop);
    auto user = get_local_user_identity();
    cancellation_point(stop);
    return user;
}

UserInteractionResult PamUserInteraction::request_presence(
    const UserIdentity& user,
    const UserInteractionRequest& request,
    std::stop_token stop,
    KeepaliveState& keepalive
) {
    (void)user;
    return collect_consent(
        presence_question(request.operation),
        stop,
        keepalive
    ) ? UserInteractionResult::approved : UserInteractionResult::denied;
}

UserInteractionResult PamUserInteraction::request_verification(
    const UserIdentity& user,
    const UserInteractionRequest& request,
    std::stop_token stop,
    KeepaliveState& keepalive
) {
    (void)request;
    return authenticate_user(
        user.name,
        processName_,
        configurationDirectory_,
        stop,
        keepalive
    ) == PAM_SUCCESS
        ? UserInteractionResult::approved
        : UserInteractionResult::denied;
}
