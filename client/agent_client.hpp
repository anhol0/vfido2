#pragma once

#include "interaction_model.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <span>

namespace vauth::client {

class AgentClient {
public:
    using EventHandler = std::function<void(InteractionEvent)>;

    explicit AgentClient(EventHandler handler);
    ~AgentClient();

    AgentClient(const AgentClient&) = delete;
    AgentClient& operator=(const AgentClient&) = delete;

    [[nodiscard]] uint64_t generation() const noexcept;
    [[nodiscard]] bool is_active(uint64_t request_id) const noexcept;

    void respond_to_presence(uint64_t request_id, bool approved);
    void submit_password(
        uint64_t request_id,
        std::span<const uint8_t> password
    );
    void cancel(uint64_t request_id);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace vauth::client
