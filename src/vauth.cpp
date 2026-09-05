#include <cerrno>
#include <array>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <optional>
#include <signal.h>
#include <stdexcept>
#include <string>
#include <system_error>
#include <string_view>
#include <utility>

#include <openssl/crypto.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <unistd.h>

#include "credentials/credential.hpp"
#include "cryptography/store_security.hpp"
#include "cryptography/tpm.hpp"
#include "device.hpp"
#include "dbus/agent_service.hpp"
#include "event.hpp"
#include "uv/src/auth.hpp"
#include "uv/src/auth_handler.hpp"

namespace {

constexpr const char* STORE_PATH = "/var/lib/vauth/credentials.v1";
constexpr const char* CREDENTIAL_NAME = "vauth-db-auth";

class UniqueFd {
public:
    explicit UniqueFd(int fd) noexcept : fd_(fd) {}
    ~UniqueFd() {
        if(fd_ >= 0) {
            ::close(fd_);
        }
    }

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    [[nodiscard]] int get() const noexcept {
        return fd_;
    }

private:
    int fd_;
};

class ShutdownSignal {
public:
    ShutdownSignal() {
        sigset_t signals;
        if(
            sigemptyset(&signals) != 0 ||
            sigaddset(&signals, SIGINT) != 0 ||
            sigaddset(&signals, SIGTERM) != 0
        ) {
            throw std::system_error(
                errno,
                std::generic_category(),
                "prepare shutdown signals"
            );
        }
        if(sigprocmask(SIG_BLOCK, &signals, &previousMask_) != 0) {
            throw std::system_error(
                errno,
                std::generic_category(),
                "block shutdown signals"
            );
        }
        maskInstalled_ = true;

        fd_ = signalfd(-1, &signals, SFD_CLOEXEC | SFD_NONBLOCK);
        if(fd_ < 0) {
            const int saved_errno = errno;
            static_cast<void>(sigprocmask(
                SIG_SETMASK,
                &previousMask_,
                nullptr
            ));
            maskInstalled_ = false;
            throw std::system_error(
                saved_errno,
                std::generic_category(),
                "create shutdown signal descriptor"
            );
        }
    }

    ~ShutdownSignal() {
        if(fd_ >= 0)
            static_cast<void>(close(fd_));
        if(maskInstalled_) {
            static_cast<void>(sigprocmask(
                SIG_SETMASK,
                &previousMask_,
                nullptr
            ));
        }
    }

    ShutdownSignal(const ShutdownSignal&) = delete;
    ShutdownSignal& operator=(const ShutdownSignal&) = delete;

    [[nodiscard]] int native_handle() const noexcept {
        return fd_;
    }

private:
    sigset_t previousMask_{};
    int fd_ = -1;
    bool maskInstalled_ = false;
};

struct Authorization {
    Authorization() = default;
    ~Authorization() {
        OPENSSL_cleanse(bytes.data(), bytes.size());
    }

    Authorization(const Authorization&) = delete;
    Authorization& operator=(const Authorization&) = delete;

    [[nodiscard]] std::string_view view() const noexcept {
        return {bytes.data(), size};
    }

    std::array<char, 34> bytes{};
    std::size_t size = 0;
};

struct Options {
    std::string command = "run";
    std::optional<std::filesystem::path> authorizationPath;
#ifdef VAUTH_DEVELOPMENT_BUILD
    bool confirmedClear = false;
#endif
};

[[noreturn]] void usage_error(const std::string& message) {
    std::string usage =
        "\nUsage: vauth [run|provision] [--auth-file PATH]";
#ifdef VAUTH_DEVELOPMENT_BUILD
    usage +=
        "\n       vauth clear-store --yes [--auth-file PATH]"
        " (Debug builds only)";
#endif
    throw std::invalid_argument(message + usage);
}

Options parse_options(int argc, char** argv) {
    Options options;
    int index = 1;
    if(index < argc && argv[index][0] != '-') {
        options.command = argv[index++];
    }
    if(
        options.command != "run" &&
        options.command != "provision"
#ifdef VAUTH_DEVELOPMENT_BUILD
        && options.command != "clear-store"
#endif
    ) {
        usage_error("Unknown command: " + options.command);
    }

    while(index < argc) {
        const std::string argument = argv[index++];
        if(argument == "--auth-file") {
            if(index >= argc) {
                usage_error("Incomplete option: --auth-file");
            }
            if(options.authorizationPath) {
                usage_error("--auth-file may be specified only once");
            }
            options.authorizationPath = argv[index++];
            continue;
        }
#ifdef VAUTH_DEVELOPMENT_BUILD
        if(argument == "--yes") {
            if(options.confirmedClear) {
                usage_error("--yes may be specified only once");
            }
            options.confirmedClear = true;
            continue;
        }
#endif
        usage_error("Unknown option: " + argument);
    }

#ifdef VAUTH_DEVELOPMENT_BUILD
    if(options.command == "clear-store" && !options.confirmedClear) {
        usage_error("clear-store requires --yes confirmation");
    }
    if(options.command != "clear-store" && options.confirmedClear) {
        usage_error("--yes is valid only with clear-store");
    }
#endif
    return options;
}

std::filesystem::path authorization_path(const Options& options) {
    if(options.authorizationPath) {
        return *options.authorizationPath;
    }

    const char* credential_directory = std::getenv("CREDENTIALS_DIRECTORY");
    if(credential_directory == nullptr || credential_directory[0] == '\0') {
        throw std::runtime_error(
            "No database authorization credential was provided; use "
            "--auth-file or the systemd vauth-db-auth credential"
        );
    }
    return std::filesystem::path(credential_directory) / CREDENTIAL_NAME;
}

void read_authorization(
    const std::filesystem::path& path,
    Authorization& authorization
) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if(fd == -1) {
        throw std::system_error(
            errno,
            std::generic_category(),
            "open database authorization credential"
        );
    }
    UniqueFd file(fd);

    struct stat status{};
    if(::fstat(file.get(), &status) == -1) {
        throw std::system_error(
            errno,
            std::generic_category(),
            "inspect database authorization credential"
        );
    }
    if(!S_ISREG(status.st_mode) || status.st_nlink != 1) {
        throw std::runtime_error(
            "Database authorization credential must be a regular file with "
            "one link"
        );
    }
    if(status.st_uid != ::geteuid() && status.st_uid != 0) {
        throw std::runtime_error(
            "Database authorization credential must be owned by root or the "
            "service user"
        );
    }
    if((status.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        throw std::runtime_error(
            "Database authorization credential must not be writable by "
            "group or others"
        );
    }
    if(status.st_size < 1 || status.st_size > 34) {
        throw std::runtime_error(
            "Database authorization credential has an invalid size"
        );
    }

    authorization.size = static_cast<std::size_t>(status.st_size);
    std::size_t offset = 0;
    while(offset < authorization.size) {
        const ssize_t count = ::read(
            file.get(),
            authorization.bytes.data() + offset,
            authorization.size - offset
        );
        if(count == -1 && errno == EINTR) {
            continue;
        }
        if(count <= 0) {
            throw std::runtime_error(
                "Could not read the database authorization credential"
            );
        }
        offset += static_cast<std::size_t>(count);
    }

    if(
        authorization.size > 0 &&
        authorization.bytes[authorization.size - 1] == '\n'
    ) {
        authorization.bytes[--authorization.size] = '\0';
    }
    if(
        authorization.size > 0 &&
        authorization.bytes[authorization.size - 1] == '\r'
    ) {
        authorization.bytes[--authorization.size] = '\0';
    }
    if(
        authorization.size == 0 ||
        authorization.size > 32 ||
        authorization.view().find('\0') != std::string_view::npos
    ) {
        throw std::runtime_error(
            "Database authorization must contain 1 to 32 non-NUL bytes"
        );
    }
}

} // namespace

int main(int argc, char** argv) {
    if(
        argc >= 2 &&
        std::string_view(argv[1]) == VAUTH_AUTH_HANDLER_COMMAND
    ) {
        return run_vauth_auth_handler(argc - 2, argv + 2);
    }

    try {
        const Options options = parse_options(argc, argv);
        std::optional<ShutdownSignal> shutdown_signal;
        if(options.command == "run")
            shutdown_signal.emplace();

        Authorization authorization;
        read_authorization(authorization_path(options), authorization);
        FapiStoreSecurity security(authorization.view());

        if(options.command == "provision") {
            security.provision();
            std::cout << "Database key and rollback counter provisioned\n";
            return 0;
        }

        CredentialStoreLock store_lock(STORE_PATH);
        auto database_key = security.unseal_key();
#ifdef VAUTH_DEVELOPMENT_BUILD
        if(options.command == "clear-store") {
            CredentialStore store(
                STORE_PATH,
                std::move(database_key),
                &security
            );
            store.load();
            store.clear();
            std::cout <<
                "Credential store cleared; TPM security objects preserved\n";
            return 0;
        }
#endif
        CredentialKeyProvider key_provider(
            security.tcti(),
            database_key
        );
        CredentialStore store(
            STORE_PATH,
            std::move(database_key),
            &security
        );
        store.load();

        vauth::dbus::AgentService agent_service;
        FIDODevice device;
        device.init();
        std::cout << "UHID device created\n";
#ifdef DEBUG
        PamUserInteraction user_interaction(
            "vauth",
            VAUTH_DEBUG_PAM_CONFIG_DIR,
            agent_service,
            agent_service
        );
#else
        PamUserInteraction user_interaction(
            "vauth",
            "/etc/vauth/config",
            agent_service,
            agent_service
        );
#endif
        run(
            device,
            store,
            key_provider,
            user_interaction,
            shutdown_signal->native_handle()
        );
        return 0;
    } catch(const std::exception& error) {
        std::cerr << "vauth: " << error.what() << '\n';
        return 1;
    }
}
