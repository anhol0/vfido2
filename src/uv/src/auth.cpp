#include <cstdio>
#include <iostream>
#include <security/_pam_types.h>
#include <security/pam_appl.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <stdint.h>

struct conv_data_t {
    std::string password;
};

void setEchoMode(bool enable) {
    struct termios tty;
    // Get the current terminal attributes
    tcgetattr(STDIN_FILENO, &tty);

    if (!enable) {
        // Clear the ECHO flag using bitwise AND-NOT
        tty.c_lflag &= ~ECHO;
    } else {
        // Set the ECHO flag using bitwise OR
        tty.c_lflag |= ECHO;
    }

    // Apply the updated attributes immediately
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

void get_data(std::string &data) {
    std::getline(std::cin, data);
}

static int myapp_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
    conv_data_t *data = (conv_data_t *)appdata_ptr;
    struct pam_response *reply = (struct pam_response*)calloc(num_msg, sizeof(struct pam_response));
    if (!reply) return PAM_BUF_ERR;

    for (int i = 0; i < num_msg; i++) {
        switch (msg[i]->msg_style) {
            case PAM_PROMPT_ECHO_OFF: { // password/PIN prompt
                // Surface this to your UI, get the PIN/password, e.g.:
                // reply[i].resp = strdup(get_pin_from_ui());
                fprintf(stderr, "[PAM] %s", msg[i]->msg);
                get_data(data->password);
                reply[i].resp = strdup(data->password.data() ? data->password.data() : "");
                break;
            }
            case PAM_TEXT_INFO:
            case PAM_ERROR_MSG:
                // e.g. fprintd sends "Scan your finger" here — show it in the UI
                fprintf(stderr, "[PAM] %s\n", msg[i]->msg);
                reply[i].resp = NULL;
                break;
            default:
                reply[i].resp = NULL;
        }
        reply[i].resp_retcode = 0;
    }
    *resp = reply;
    return PAM_SUCCESS;
}

int authenticate_user(
    const std::string &username,
    const std::string &process_name,
    const std::string &confdir
) {
    pam_handle_t *pamh = NULL;
    conv_data_t data {};
    struct pam_conv conv = { &myapp_conv, &data };
    int rc = pam_start_confdir(process_name.c_str(), username.c_str(), &conv, confdir.c_str(), &pamh);
    if(rc != PAM_SUCCESS) {
        std::cout << "Incorrect config path or user name!\n";
        return rc;
    }
    rc = pam_authenticate(pamh, 0);
    if(rc == PAM_SUCCESS)
        rc = pam_acct_mgmt(pamh, 0);

    pam_end(pamh, 0);
    return rc;
}

bool collect_consent(const std::string question) {
    pid_t pid = fork();
    if (pid < 0) return false;

    if (pid == 0) {
        std::string arg = "--text=" + question;
        execlp("zenity", "zenity", "--question", arg.c_str(), (char*)nullptr);
        _exit(127); // exec failed
    }

    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

std::string get_user_name() {
    char *name = getlogin();
    size_t len = strlen(name);
    return std::string(name, len);
}
