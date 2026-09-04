#include "cancellation.hpp"
#include "keepalive.hpp"
#include "test_runner.hpp"
#include "uv/src/auth.hpp"

#include <chrono>
#include <iostream>
#include <optional>
#include <stop_token>

namespace {

#define CHECK(condition) do { \
    if(!(condition)) { \
        std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ \
                  << ": " #condition "\n"; \
        return false; \
    } \
} while(false)

UserContext registered_user() {
    return {
        .uid = 1000,
        .name = "alice",
        .session = UserSessionContext{
            .sessionId = "session-2",
            .interactionAgentId = ":1.42",
            .generation = 1
        }
    };
}

class TestProvider final : public UserContextProvider {
public:
    std::optional<UserContext> context;

    [[nodiscard]] std::optional<UserContext> current_context() override {
        return context;
    }
};

class TestChannel final : public UserInteractionChannel {
public:
    uint64_t nextRequestId = 1;
    bool waitedForPresence = false;

    [[nodiscard]] uint64_t begin_interaction(
        const UserContext&,
        const UserInteractionRequest&
    ) override {
        return nextRequestId;
    }

    void publish_state(
        const UserContext&,
        const UserInteractionRequest&,
        UserInteractionState
    ) override {}

    void end_interaction(
        const UserContext&,
        const UserInteractionRequest&
    ) noexcept override {}

    [[nodiscard]] UserInteractionResult wait_for_presence(
        const UserContext&,
        const UserInteractionRequest&,
        std::stop_token,
        std::chrono::steady_clock::duration
    ) override {
        waitedForPresence = true;
        return UserInteractionResult::approved;
    }

    [[nodiscard]] vauth::uv::SensitiveBytes wait_for_password(
        const UserContext&,
        const UserInteractionRequest&,
        std::stop_token,
        std::chrono::steady_clock::duration
    ) override {
        return {};
    }

    [[nodiscard]] bool cancellation_requested(
        const UserContext&,
        const UserInteractionRequest&
    ) const noexcept override {
        return false;
    }
};

bool test_no_registered_agent_fails_closed() {
    TestProvider provider;
    TestChannel channel;
    PamUserInteraction interaction("vauth", "/tmp", provider, channel);

    try {
        static_cast<void>(interaction.current_context({}));
    } catch(const UserInteractionUnavailable&) {
        return true;
    }
    return false;
}

bool test_registered_agent_supplies_context() {
    TestProvider provider;
    provider.context = registered_user();
    TestChannel channel;
    PamUserInteraction interaction("vauth", "/tmp", provider, channel);

    const UserContext context = interaction.current_context({});
    CHECK(context.binding() == provider.context->binding());
    CHECK(context.name == "alice");
    return true;
}

bool test_agent_loss_before_interaction_fails_closed() {
    TestProvider provider;
    const UserContext user = registered_user();
    provider.context = user;
    TestChannel channel;
    channel.nextRequestId = 0;
    PamUserInteraction interaction("vauth", "/tmp", provider, channel);
    KeepaliveState keepalive;
    const UserInteractionRequest request{
        .operation = UserInteractionOperation::make_credential,
        .relyingPartyId = "example.com"
    };

    try {
        static_cast<void>(interaction.request_presence(
            user,
            request,
            {},
            keepalive
        ));
    } catch(const UserInteractionUnavailable&) {
        CHECK(!channel.waitedForPresence);
        CHECK(keepalive.get() == KeepaliveStatus::processing);
        return true;
    }
    return false;
}

} // namespace

int main() {
    test_support::Runner runner;
    runner.run(
        "no registered agent fails closed",
        test_no_registered_agent_fails_closed
    );
    runner.run(
        "registered agent supplies context",
        test_registered_agent_supplies_context
    );
    runner.run(
        "agent loss before interaction fails closed",
        test_agent_loss_before_interaction_fails_closed
    );
    return runner.finish();
}
