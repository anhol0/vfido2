#include "auth_handler.hpp"

#include <security/_pam_types.h>
#include <security/pam_appl.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <strings.h>
#include <termios.h>
#include <unistd.h>

namespace {

class TerminalState {
public:
    TerminalState() noexcept {
        valid_ = tcgetattr(STDIN_FILENO, &original_) == 0;
    }

    ~TerminalState() {
        restore();
    }

    TerminalState(const TerminalState&) = delete;
    TerminalState& operator=(const TerminalState&) = delete;

    bool disable_echo() noexcept {
        if(!valid_)
            return false;
        termios hidden = original_;
        hidden.c_lflag &= static_cast<tcflag_t>(~ECHO);
        return tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) == 0;
    }

    bool restore() noexcept {
        if(!valid_ || restored_)
            return true;
        if(tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_) != 0)
            return false;
        restored_ = true;
        return true;
    }

private:
    termios original_{};
    bool valid_ = false;
    bool restored_ = false;
};

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

int read_response(const pam_message& message, bool hide, char** response) {
    if(response == nullptr)
        return PAM_CONV_ERR;

    if(message.msg != nullptr)
        std::fprintf(stderr, "[PAM] %s\n", message.msg);

    TerminalState terminal;
    if(hide && !terminal.disable_echo())
        return PAM_CONV_ERR;

    constexpr std::size_t maximum_response_size = 1024;
    std::array<char, maximum_response_size + 1> input{};
    if(!std::cin.getline(input.data(), input.size())) {
        explicit_bzero(input.data(), input.size());
        return PAM_CONV_ERR;
    }
    if(!terminal.restore()) {
        explicit_bzero(input.data(), input.size());
        return PAM_CONV_ERR;
    }
    if(hide)
        std::fputc('\n', stderr);

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
    void*
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
                    rc = read_response(*messages[i], true, &replies[i].resp);
                    break;
                case PAM_PROMPT_ECHO_ON:
                    rc = read_response(*messages[i], false, &replies[i].resp);
                    break;
                case PAM_TEXT_INFO:
                case PAM_ERROR_MSG:
                    if(messages[i]->msg != nullptr)
                        std::fprintf(stderr, "[PAM] %s\n", messages[i]->msg);
                    break;
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
    const pam_conv conv{&conversation, nullptr};
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
