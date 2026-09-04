#include "agent_registry.hpp"

#include <limits>
#include <stdexcept>
#include <utility>

namespace vauth::dbus {
namespace {

bool same_peer(const UserContext& context, const AgentPeer& peer) {
    return
        context.uid == peer.uid &&
        context.name == peer.userName &&
        context.session &&
        context.session->sessionId == peer.sessionId &&
        context.session->interactionAgentId == peer.busName;
}

void validate_peer(const AgentPeer& peer) {
    if(
        peer.userName.empty() ||
        peer.sessionId.empty() ||
        peer.busName.empty() ||
        peer.busName.front() != ':'
    ) {
        throw std::invalid_argument("Invalid user-interaction agent identity");
    }
}

}

UserContext AgentRegistry::register_agent(AgentPeer peer) {
    validate_peer(peer);
    std::lock_guard lock(mutex_);

    if(current_) {
        if(same_peer(*current_, peer))
            return *current_;
        throw std::runtime_error(
            "Another user-interaction agent is already registered"
        );
    }
    if(
        nextGeneration_ == 0 ||
        nextGeneration_ == std::numeric_limits<uint64_t>::max()
    ) {
        throw std::overflow_error(
            "User-interaction agent generation is exhausted"
        );
    }

    current_ = UserContext{
        .uid = peer.uid,
        .name = std::move(peer.userName),
        .session = UserSessionContext{
            .sessionId = std::move(peer.sessionId),
            .interactionAgentId = std::move(peer.busName),
            .generation = nextGeneration_++
        }
    };
    return *current_;
}

bool AgentRegistry::unregister_agent(std::string_view bus_name) {
    std::lock_guard lock(mutex_);
    if(
        !current_ ||
        !current_->session ||
        current_->session->interactionAgentId != bus_name
    ) {
        return false;
    }
    current_.reset();
    return true;
}

std::optional<UserContext> AgentRegistry::current_context() const {
    std::lock_guard lock(mutex_);
    return current_;
}

bool AgentRegistry::is_current(const UserContext& context) const {
    std::lock_guard lock(mutex_);
    return current_ && current_->binding() == context.binding();
}

}
