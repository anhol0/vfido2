#include "dbus/agent_registry.hpp"
#include "dbus/interaction_registry.hpp"
#include "dbus/secret_pipe.hpp"
#include "test_runner.hpp"
#include "uv/src/user_interaction.hpp"

#include <algorithm>
#include <chrono>
#include <cerrno>
#include <fcntl.h>
#include <iostream>
#include <span>
#include <stop_token>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

#define CHECK(condition) do { \
    if(!(condition)) { \
        std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ \
                  << ": " #condition "\n"; \
        return false; \
    } \
} while(false)

class TestFd {
public:
    explicit TestFd(int fd = -1) noexcept : fd_(fd) {}

    ~TestFd() {
        if(fd_ >= 0)
            static_cast<void>(close(fd_));
    }

    TestFd(const TestFd&) = delete;
    TestFd& operator=(const TestFd&) = delete;

    TestFd(TestFd&& other) noexcept
        : fd_(std::exchange(other.fd_, -1)) {}

    TestFd& operator=(TestFd&& other) noexcept {
        if(this != &other) {
            reset();
            fd_ = std::exchange(other.fd_, -1);
        }
        return *this;
    }

    [[nodiscard]] int get() const noexcept {
        return fd_;
    }

    void reset(int fd = -1) noexcept {
        if(fd_ >= 0)
            static_cast<void>(close(fd_));
        fd_ = fd;
    }

private:
    int fd_;
};

vauth::uv::SensitiveBytes sensitive(std::string_view value) {
    vauth::uv::SensitiveBytes result(value.size());
    std::ranges::copy(value, result.writable_bytes().begin());
    return result;
}

std::pair<TestFd, TestFd> make_pipe() {
    int descriptors[2]{};
    if(pipe2(descriptors, O_CLOEXEC) != 0)
        throw std::runtime_error("Unable to create test pipe");
    return {TestFd(descriptors[0]), TestFd(descriptors[1])};
}

void write_all(int fd, std::span<const uint8_t> bytes) {
    std::size_t written = 0;
    while(written < bytes.size()) {
        const ssize_t count = write(
            fd,
            bytes.data() + written,
            bytes.size() - written
        );
        if(count > 0) {
            written += static_cast<std::size_t>(count);
            continue;
        }
        if(count < 0 && errno == EINTR)
            continue;
        throw std::runtime_error("Unable to write test pipe");
    }
}

vauth::dbus::AgentPeer peer(
    std::string bus_name = ":1.42",
    std::string session_id = "session-2"
) {
    return {
        .uid = 1000,
        .userName = "alice",
        .sessionId = std::move(session_id),
        .busName = std::move(bus_name)
    };
}

bool test_registration_lifetime() {
    vauth::dbus::AgentRegistry registry;

    const UserContext first = registry.register_agent(peer());
    CHECK(first.uid == 1000);
    CHECK(first.name == "alice");
    CHECK(first.session.has_value());
    CHECK(first.session->sessionId == "session-2");
    CHECK(first.session->interactionAgentId == ":1.42");
    CHECK(first.session->generation == 1);
    CHECK(registry.is_current(first));

    const UserContext repeated = registry.register_agent(peer());
    CHECK(repeated.name == first.name);
    CHECK(repeated.binding() == first.binding());

    bool competing_rejected = false;
    try {
        static_cast<void>(registry.register_agent(peer(":1.43")));
    } catch(const std::runtime_error&) {
        competing_rejected = true;
    }
    CHECK(competing_rejected);
    CHECK(!registry.unregister_agent(":1.43"));
    CHECK(registry.unregister_agent(":1.42"));
    CHECK(!registry.current_context().has_value());
    CHECK(!registry.is_current(first));

    const UserContext second = registry.register_agent(peer(":1.43"));
    CHECK(second.session->generation == 2);
    CHECK(registry.is_current(second));
    CHECK(!registry.is_current(first));
    return true;
}

bool test_invalid_identity_rejected() {
    const auto rejected = [](vauth::dbus::AgentPeer invalid_peer) {
        vauth::dbus::AgentRegistry registry;
        try {
            static_cast<void>(registry.register_agent(
                std::move(invalid_peer)
            ));
        } catch(const std::invalid_argument&) {
            return true;
        }
        return false;
    };

    auto no_name = peer();
    no_name.userName.clear();
    CHECK(rejected(std::move(no_name)));

    auto no_session = peer();
    no_session.sessionId.clear();
    CHECK(rejected(std::move(no_session)));

    auto no_bus_name = peer();
    no_bus_name.busName.clear();
    CHECK(rejected(std::move(no_bus_name)));

    auto well_known_name = peer();
    well_known_name.busName = "org.example.Agent";
    CHECK(rejected(std::move(well_known_name)));
    return true;
}

bool test_wait_for_registration() {
    vauth::dbus::AgentRegistry registry;
    std::jthread registrar([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        static_cast<void>(registry.register_agent(peer()));
    });

    const auto context = registry.wait_for_current(
        std::chrono::seconds(1)
    );
    registrar.join();
    CHECK(context.has_value());
    CHECK(context->session.has_value());
    CHECK(context->session->interactionAgentId == ":1.42");

    vauth::dbus::AgentRegistry empty;
    const auto started = std::chrono::steady_clock::now();
    CHECK(!empty.wait_for_current(std::chrono::milliseconds(20)));
    CHECK(
        std::chrono::steady_clock::now() - started >=
        std::chrono::milliseconds(15)
    );
    return true;
}

bool test_state_names() {
    CHECK(
        user_interaction_operation_name(
            UserInteractionOperation::make_credential
        ) == "make_credential"
    );
    CHECK(
        user_interaction_state_name(
            UserInteractionState::fingerprint_failed
        ) == "fingerprint_failed"
    );
    CHECK(
        user_interaction_state_name(
            UserInteractionState::password_required
        ) == "password_required"
    );
    return true;
}

bool test_interaction_lifecycle() {
    vauth::dbus::AgentRegistry agents;
    vauth::dbus::InteractionRegistry interactions;
    const UserContext user = agents.register_agent(peer());

    const uint64_t first_id = interactions.begin(
        user,
        UserInteractionOperation::make_credential,
        "example.com"
    );
    CHECK(first_id != 0);
    auto pending = interactions.current();
    CHECK(pending.has_value());
    CHECK(pending->requestId == first_id);
    CHECK(pending->user == user.binding());
    CHECK(pending->operation == UserInteractionOperation::make_credential);
    CHECK(pending->relyingPartyId == "example.com");
    CHECK(!pending->state.has_value());

    bool competing_rejected = false;
    try {
        static_cast<void>(interactions.begin(
            user,
            UserInteractionOperation::get_assertion,
            "example.com"
        ));
    } catch(const std::runtime_error&) {
        competing_rejected = true;
    }
    CHECK(competing_rejected);

    CHECK(interactions.transition(
        user,
        first_id,
        UserInteractionState::verification_started
    ));
    CHECK(interactions.transition(
        user,
        first_id,
        UserInteractionState::fingerprint_required
    ));
    CHECK(interactions.transition(
        user,
        first_id,
        UserInteractionState::fingerprint_failed
    ));
    CHECK(interactions.transition(
        user,
        first_id,
        UserInteractionState::password_required
    ));
    CHECK(interactions.transition(
        user,
        first_id,
        UserInteractionState::verification_succeeded
    ));
    CHECK(!interactions.current().has_value());

    bool stale_rejected = false;
    try {
        static_cast<void>(interactions.transition(
            user,
            first_id,
            UserInteractionState::verification_failed
        ));
    } catch(const std::runtime_error&) {
        stale_rejected = true;
    }
    CHECK(stale_rejected);

    const uint64_t second_id = interactions.begin(
        user,
        UserInteractionOperation::get_assertion,
        "example.com"
    );
    CHECK(second_id > first_id);
    CHECK(interactions.end(user, second_id));
    CHECK(!interactions.current().has_value());
    return true;
}

bool test_interaction_transition_validation() {
    vauth::dbus::AgentRegistry agents;
    vauth::dbus::InteractionRegistry interactions;
    const UserContext user = agents.register_agent(peer());
    const uint64_t request_id = interactions.begin(
        user,
        UserInteractionOperation::check_excluded_credential,
        "example.com"
    );

    CHECK(interactions.transition(
        user,
        request_id,
        UserInteractionState::presence_required
    ));
    bool invalid_rejected = false;
    try {
        static_cast<void>(interactions.transition(
            user,
            request_id,
            UserInteractionState::fingerprint_required
        ));
    } catch(const std::logic_error&) {
        invalid_rejected = true;
    }
    CHECK(invalid_rejected);
    CHECK(
        interactions.current()->state ==
        UserInteractionState::presence_required
    );

    UserContext wrong_user = user;
    wrong_user.uid = 1001;
    CHECK(!interactions.end(wrong_user, request_id));
    interactions.clear_for(wrong_user);
    CHECK(interactions.current().has_value());

    CHECK(interactions.transition(
        user,
        request_id,
        UserInteractionState::presence_denied
    ));
    CHECK(!interactions.current().has_value());
    return true;
}

bool test_presence_responses_and_cancellation() {
    vauth::dbus::AgentRegistry agents;
    vauth::dbus::InteractionRegistry interactions;
    const UserContext user = agents.register_agent(peer());

    const uint64_t presence_id = interactions.begin(
        user,
        UserInteractionOperation::make_credential,
        "example.com"
    );
    CHECK(interactions.transition(
        user,
        presence_id,
        UserInteractionState::presence_required
    ));
    std::jthread responder([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        interactions.respond_to_presence(user, presence_id, true);
    });
    std::stop_source stop;
    CHECK(
        interactions.wait_for_presence(
            user,
            presence_id,
            stop.get_token(),
            std::chrono::seconds(1)
        ) == vauth::dbus::PresenceWaitResult::approved
    );
    responder.join();

    bool duplicate_rejected = false;
    try {
        interactions.respond_to_presence(user, presence_id, false);
    } catch(const std::runtime_error&) {
        duplicate_rejected = true;
    }
    CHECK(duplicate_rejected);
    CHECK(interactions.transition(
        user,
        presence_id,
        UserInteractionState::presence_approved
    ));

    const uint64_t verification_id = interactions.begin(
        user,
        UserInteractionOperation::get_assertion,
        "example.com"
    );
    CHECK(interactions.transition(
        user,
        verification_id,
        UserInteractionState::verification_started
    ));
    CHECK(!interactions.cancellation_requested(user, verification_id));
    interactions.request_cancel(user, verification_id);
    CHECK(interactions.cancellation_requested(user, verification_id));
    CHECK(
        interactions.wait_for_presence(
            user,
            verification_id,
            stop.get_token(),
            std::chrono::seconds(1)
        ) == vauth::dbus::PresenceWaitResult::client_cancelled
    );
    CHECK(!interactions.transition(
        user,
        verification_id,
        UserInteractionState::fingerprint_required
    ));
    CHECK(interactions.transition(
        user,
        verification_id,
        UserInteractionState::cancelled
    ));

    const uint64_t timeout_id = interactions.begin(
        user,
        UserInteractionOperation::check_excluded_credential,
        "example.com"
    );
    CHECK(interactions.transition(
        user,
        timeout_id,
        UserInteractionState::presence_required
    ));
    CHECK(
        interactions.wait_for_presence(
            user,
            timeout_id,
            stop.get_token(),
            std::chrono::milliseconds(1)
        ) == vauth::dbus::PresenceWaitResult::timed_out
    );
    bool late_response_rejected = false;
    try {
        interactions.respond_to_presence(user, timeout_id, true);
    } catch(const std::runtime_error&) {
        late_response_rejected = true;
    }
    CHECK(late_response_rejected);
    CHECK(interactions.transition(
        user,
        timeout_id,
        UserInteractionState::timed_out
    ));
    return true;
}

bool test_password_responses() {
    vauth::dbus::AgentRegistry agents;
    vauth::dbus::InteractionRegistry interactions;
    const UserContext user = agents.register_agent(peer());
    const uint64_t request_id = interactions.begin(
        user,
        UserInteractionOperation::get_assertion,
        "example.com"
    );
    CHECK(interactions.transition(
        user,
        request_id,
        UserInteractionState::verification_started
    ));

    bool early_response_rejected = false;
    try {
        interactions.submit_password(
            user,
            request_id,
            sensitive("too-early")
        );
    } catch(const std::runtime_error&) {
        early_response_rejected = true;
    }
    CHECK(early_response_rejected);
    CHECK(interactions.transition(
        user,
        request_id,
        UserInteractionState::password_required
    ));

    UserContext wrong_user = user;
    wrong_user.uid = 1001;
    bool wrong_user_rejected = false;
    try {
        interactions.submit_password(
            wrong_user,
            request_id,
            sensitive("foreign")
        );
    } catch(const std::runtime_error&) {
        wrong_user_rejected = true;
    }
    CHECK(wrong_user_rejected);

    std::jthread responder([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        interactions.submit_password(user, request_id, sensitive("secret"));
    });
    std::stop_source stop;
    auto response = interactions.wait_for_password(
        user,
        request_id,
        stop.get_token(),
        std::chrono::seconds(1)
    );
    responder.join();
    CHECK(response.status == vauth::dbus::PasswordWaitStatus::provided);
    const std::vector<uint8_t> expected{'s', 'e', 'c', 'r', 'e', 't'};
    CHECK(std::ranges::equal(response.password.bytes(), expected));

    bool duplicate_rejected = false;
    try {
        interactions.submit_password(
            user,
            request_id,
            sensitive("duplicate")
        );
    } catch(const std::runtime_error&) {
        duplicate_rejected = true;
    }
    CHECK(duplicate_rejected);
    CHECK(interactions.transition(
        user,
        request_id,
        UserInteractionState::verification_succeeded
    ));

    const uint64_t cancelled_id = interactions.begin(
        user,
        UserInteractionOperation::make_credential,
        "example.com"
    );
    CHECK(interactions.transition(
        user,
        cancelled_id,
        UserInteractionState::verification_started
    ));
    CHECK(interactions.transition(
        user,
        cancelled_id,
        UserInteractionState::password_required
    ));
    interactions.request_cancel(user, cancelled_id);
    auto cancelled = interactions.wait_for_password(
        user,
        cancelled_id,
        stop.get_token(),
        std::chrono::seconds(1)
    );
    CHECK(
        cancelled.status ==
        vauth::dbus::PasswordWaitStatus::client_cancelled
    );
    CHECK(interactions.transition(
        user,
        cancelled_id,
        UserInteractionState::cancelled
    ));
    return true;
}

bool test_password_pipe_validation() {
    {
        auto [read_end, write_end] = make_pipe();
        const std::vector<uint8_t> expected{'s', 'e', 'c', 'r', 'e', 't'};
        write_all(write_end.get(), expected);
        write_end.reset();
        auto password = vauth::dbus::read_secret_pipe(read_end.get());
        CHECK(std::ranges::equal(password.bytes(), expected));
    }

    {
        auto [read_end, write_end] = make_pipe();
        const std::vector<uint8_t> incomplete{'x'};
        write_all(write_end.get(), incomplete);
        bool rejected = false;
        try {
            static_cast<void>(
                vauth::dbus::read_secret_pipe(read_end.get())
            );
        } catch(const std::invalid_argument&) {
            rejected = true;
        }
        CHECK(rejected);
    }

    {
        auto [read_end, write_end] = make_pipe();
        const std::vector<uint8_t> maximum(
            vauth::uv::MAX_PASSWORD_SIZE,
            'x'
        );
        write_all(write_end.get(), maximum);
        write_end.reset();
        auto password = vauth::dbus::read_secret_pipe(read_end.get());
        CHECK(password.size() == vauth::uv::MAX_PASSWORD_SIZE);
    }

    {
        auto [read_end, write_end] = make_pipe();
        const std::vector<uint8_t> oversized(
            vauth::uv::MAX_PASSWORD_SIZE + 1,
            'x'
        );
        write_all(write_end.get(), oversized);
        write_end.reset();
        bool rejected = false;
        try {
            static_cast<void>(
                vauth::dbus::read_secret_pipe(read_end.get())
            );
        } catch(const std::invalid_argument&) {
            rejected = true;
        }
        CHECK(rejected);
    }

    {
        auto [read_end, write_end] = make_pipe();
        const std::vector<uint8_t> embedded_nul{'a', 0, 'b'};
        write_all(write_end.get(), embedded_nul);
        write_end.reset();
        bool rejected = false;
        try {
            static_cast<void>(
                vauth::dbus::read_secret_pipe(read_end.get())
            );
        } catch(const std::invalid_argument&) {
            rejected = true;
        }
        CHECK(rejected);
    }

    TestFd regular(open("/dev/null", O_RDONLY | O_CLOEXEC));
    CHECK(regular.get() >= 0);
    bool regular_rejected = false;
    try {
        static_cast<void>(vauth::dbus::read_secret_pipe(regular.get()));
    } catch(const std::invalid_argument&) {
        regular_rejected = true;
    }
    CHECK(regular_rejected);
    return true;
}

}

int main() {
    test_support::Runner runner;
    runner.run("test_registration_lifetime", test_registration_lifetime);
    runner.run("test_invalid_identity_rejected", test_invalid_identity_rejected);
    runner.run("test_wait_for_registration", test_wait_for_registration);
    runner.run("test_state_names", test_state_names);
    runner.run("test_interaction_lifecycle", test_interaction_lifecycle);
    runner.run(
        "test_interaction_transition_validation",
        test_interaction_transition_validation
    );
    runner.run(
        "test_presence_responses_and_cancellation",
        test_presence_responses_and_cancellation
    );
    runner.run("test_password_responses", test_password_responses);
    runner.run(
        "test_password_pipe_validation",
        test_password_pipe_validation
    );
    return runner.finish();
}
