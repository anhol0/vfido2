#include "auth_handler.hpp"
#include "auth_handler_status.hpp"
#include "sensitive_bytes.hpp"

#include <security/_pam_types.h>
#include <security/pam_appl.h>

#include <array>
#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <strings.h>
#include <unistd.h>

namespace {

struct ConversationContext {
    bool fingerprintPrompted = false;
};

void send_status(vauth::uv::AuthHandlerStatus status) noexcept {
    const uint8_t value = static_cast<uint8_t>(status);
    ssize_t result;
    do {
        result = write(
            vauth::uv::AUTH_HANDLER_STATUS_FD,
            &value,
            sizeof(value)
        );
    } while(result < 0 && errno == EINTR);
}

std::string lowercase(std::string_view text) {
    std::string result(text);
    std::transform(
        result.begin(),
        result.end(),
        result.begin(),
        [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        }
    );
    return result;
}

bool mentions_fingerprint(std::string_view message) {
    return
        message.find("finger") != std::string_view::npos ||
        message.find("swipe") != std::string_view::npos;
}

bool reports_failure(std::string_view message) {
    return
        message.find("fail") != std::string_view::npos ||
        message.find("not recognized") != std::string_view::npos ||
        message.find("no match") != std::string_view::npos ||
        message.find("try again") != std::string_view::npos;
}

void free_responses(pam_response* responses, int count) noexcept {
    if(responses == nullptr)
        return;
    for(int i = 0; i < count; ++i) {
        if(responses[i].resp != nullptr) {
            explicit_bzero(responses[i].resp, std::strlen(responses[i].resp));
            std::free(responses[i].resp);
        }
    }
    std::free(responses);
}

int read_password_response(char** response) {
    if(
        response == nullptr ||
        fcntl(vauth::uv::AUTH_HANDLER_RESPONSE_FD, F_GETFD) < 0
    ) {
        return PAM_CONV_ERR;
    }

    send_status(vauth::uv::AuthHandlerStatus::password_required);
    std::array<char, vauth::uv::MAX_PASSWORD_SIZE + 1> input{};
    std::size_t used = 0;
    while(true) {
        const ssize_t count = read(
            vauth::uv::AUTH_HANDLER_RESPONSE_FD,
            input.data() + used,
            input.size() - used
        );
        if(count > 0) {
            used += static_cast<std::size_t>(count);
            if(used > vauth::uv::MAX_PASSWORD_SIZE) {
                explicit_bzero(input.data(), input.size());
                return PAM_CONV_ERR;
            }
            continue;
        }
        if(count == 0)
            break;
        if(errno == EINTR)
            continue;
        explicit_bzero(input.data(), input.size());
        return PAM_CONV_ERR;
    }
    if(std::memchr(input.data(), '\0', used) != nullptr) {
        explicit_bzero(input.data(), input.size());
        return PAM_CONV_ERR;
    }
    input[used] = '\0';
    char* copy = ::strdup(input.data());
    explicit_bzero(input.data(), input.size());
    if(copy == nullptr)
        return PAM_BUF_ERR;
    *response = copy;
    return PAM_SUCCESS;
}

int conversation(
    int message_count,
    const pam_message** messages,
    pam_response** response,
    void* user_data
) noexcept {
    if(
        message_count <= 0 ||
        message_count > PAM_MAX_NUM_MSG ||
        messages == nullptr ||
        response == nullptr
    ) {
        return PAM_CONV_ERR;
    }
    *response = nullptr;
    auto* context = static_cast<ConversationContext*>(user_data);

    auto* replies = static_cast<pam_response*>(
        std::calloc(static_cast<std::size_t>(message_count), sizeof(pam_response))
    );
    if(replies == nullptr)
        return PAM_BUF_ERR;

    try {
        for(int i = 0; i < message_count; ++i) {
            if(messages[i] == nullptr) {
                free_responses(replies, message_count);
                return PAM_CONV_ERR;
            }

            int rc = PAM_SUCCESS;
            switch(messages[i]->msg_style) {
                case PAM_PROMPT_ECHO_OFF:
                    rc = read_password_response(&replies[i].resp);
                    break;
                case PAM_PROMPT_ECHO_ON:
                    // The daemon never obtains identity or other visible PAM
                    // responses from inherited standard input.
                    rc = PAM_CONV_ERR;
                    break;
                case PAM_TEXT_INFO:
                case PAM_ERROR_MSG: {
                    const std::string normalized = lowercase(
                        messages[i]->msg == nullptr ? "" : messages[i]->msg
                    );
                    if(mentions_fingerprint(normalized)) {
                        if(context != nullptr)
                            context->fingerprintPrompted = true;
                        send_status(
                            reports_failure(normalized)
                                ? vauth::uv::AuthHandlerStatus::fingerprint_failed
                                : vauth::uv::AuthHandlerStatus::fingerprint_required
                        );
                    } else if(
                        context != nullptr &&
                        context->fingerprintPrompted &&
                        reports_failure(normalized)
                    ) {
                        send_status(
                            vauth::uv::AuthHandlerStatus::fingerprint_failed
                        );
                    }
                    break;
                }
                default:
                    rc = PAM_CONV_ERR;
                    break;
            }
            if(rc != PAM_SUCCESS) {
                free_responses(replies, message_count);
                return rc;
            }
        }
    } catch(...) {
        free_responses(replies, message_count);
        return PAM_CONV_ERR;
    }

    *response = replies;
    return PAM_SUCCESS;
}

class PamSession {
public:
    PamSession() = default;

    ~PamSession() {
        close(status_);
    }

    PamSession(const PamSession&) = delete;
    PamSession& operator=(const PamSession&) = delete;

    int start(
        const char* process_name,
        const char* username,
        const pam_conv* conv,
        const char* confdir
    ) noexcept {
        pam_handle_t* handle = nullptr;
        const int rc = pam_start_confdir(
            process_name,
            username,
            conv,
            confdir,
            &handle
        );
        handle_ = handle;
        status_ = rc;
        return rc;
    }

    pam_handle_t* get() noexcept {
        return handle_;
    }

    void set_status(int status) noexcept {
        status_ = status;
    }

    int close(int status) noexcept {
        if(handle_ == nullptr)
            return PAM_SUCCESS;
        pam_handle_t* handle = handle_;
        handle_ = nullptr;
        return pam_end(handle, status);
    }

private:
    pam_handle_t* handle_ = nullptr;
    int status_ = PAM_SYSTEM_ERR;
};

int authenticate(
    const char* username,
    const char* process_name,
    const char* confdir
) {
    ConversationContext context;
    const pam_conv conv{&conversation, &context};
    PamSession session;
    int rc = session.start(
        process_name,
        username,
        &conv,
        confdir
    );
    if(rc == PAM_SUCCESS)
        rc = pam_authenticate(session.get(), 0);
    if(rc == PAM_SUCCESS)
        rc = pam_acct_mgmt(session.get(), 0);
    session.set_status(rc);

    const int end_rc = session.close(rc);
    if(rc == PAM_SUCCESS && end_rc != PAM_SUCCESS)
        return end_rc;
    return rc;
}

}

int run_vauth_auth_handler(int argc, char** argv) noexcept {
    if(argc != 3 || argv == nullptr)
        return PAM_SYSTEM_ERR;

    try {
        return authenticate(argv[0], argv[1], argv[2]);
    } catch(...) {
        return PAM_SYSTEM_ERR;
    }
}
