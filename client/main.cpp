#include "agent_client.hpp"
#include "animation_data.hpp"
#include "appwindow.h"
#include "interaction_model.hpp"
#include "uv/src/sensitive_bytes.hpp"

#include <rlottie.h>
#include <slint.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/prctl.h>
#include <utility>
#include <vector>

namespace {

constexpr float ANIMATION_LOGICAL_WIDTH = 145.0F;
constexpr float ANIMATION_LOGICAL_HEIGHT = 145.0F;
constexpr std::size_t MAX_PASSWORD_SIZE = 1024;
constexpr std::size_t MAX_STARTUP_EVENTS = 32;

struct FingerprintAnimations {
    std::unique_ptr<rlottie::Animation> waiting;
    std::unique_ptr<rlottie::Animation> success;
    std::unique_ptr<rlottie::Animation> failure;

    [[nodiscard]] rlottie::Animation* for_kind(std::string_view kind) const {
        if(kind == "success")
            return success.get();
        if(kind == "failure")
            return failure.get();
        return waiting.get();
    }
};

struct UiRuntime {
    explicit UiRuntime(slint::ComponentHandle<AppWindow> handle)
        : ui(std::move(handle)) {}

    slint::ComponentHandle<AppWindow> ui;
    vauth::client::UiModel model;
    slint::Timer terminalTimer;
    slint::Timer renderTimer;
    std::function<void()> renderTick;
    uint64_t activeRequestId = 0;
    uint64_t presentationRevision = 0;
};

struct UiStartup {
    std::mutex mutex;
    std::condition_variable eventAvailable;
    std::deque<vauth::client::InteractionEvent> events;
    bool eventLoopStarted = false;
    bool overflowed = false;
};

std::unique_ptr<rlottie::Animation> load_animation(std::string_view data) {
    return rlottie::Animation::loadFromData(std::string(data), "");
}

slint::Image render_frame(
    rlottie::Animation& animation,
    std::size_t frame,
    std::size_t pixel_width,
    std::size_t pixel_height
) {
    std::vector<uint32_t> lottie_buffer(pixel_width * pixel_height);
    rlottie::Surface surface(
        lottie_buffer.data(),
        pixel_width,
        pixel_height,
        pixel_width * sizeof(uint32_t)
    );
    animation.renderSync(frame, surface);

    slint::SharedPixelBuffer<slint::Rgba8Pixel> pixels(
        pixel_width,
        pixel_height
    );
    auto* destination = pixels.begin();
    for(std::size_t index = 0; index < lottie_buffer.size(); ++index) {
        const uint32_t pixel = lottie_buffer[index];
        destination[index] = {
            static_cast<uint8_t>((pixel >> 16) & 0xff),
            static_cast<uint8_t>((pixel >> 8) & 0xff),
            static_cast<uint8_t>(pixel & 0xff),
            static_cast<uint8_t>((pixel >> 24) & 0xff)
        };
    }
    return slint::Image(pixels);
}

std::string_view view_name(vauth::client::ViewKind view) noexcept {
    switch(view) {
        case vauth::client::ViewKind::presence:
            return "presence";
        case vauth::client::ViewKind::fingerprint:
            return "fingerprint";
        case vauth::client::ViewKind::password:
            return "password";
        case vauth::client::ViewKind::status:
            return "status";
    }
    return "status";
}

std::string_view animation_name(
    vauth::client::AnimationKind animation
) noexcept {
    switch(animation) {
        case vauth::client::AnimationKind::none:
            return "none";
        case vauth::client::AnimationKind::waiting:
            return "waiting";
        case vauth::client::AnimationKind::success:
            return "success";
        case vauth::client::AnimationKind::failure:
            return "failure";
    }
    return "none";
}

void show_event(
    const std::shared_ptr<UiRuntime>& runtime,
    vauth::client::InteractionEvent event
) {
    if(!runtime->ui->window().is_visible()) {
        runtime->ui->set_remap_constraint_toggle(
            !runtime->ui->get_remap_constraint_toggle()
        );
    }
    const auto presentation = runtime->model.apply(event);
    const uint64_t revision = ++runtime->presentationRevision;
    runtime->activeRequestId = presentation.terminal ? 0 : event.requestId;

    runtime->ui->set_view(slint::SharedString(view_name(presentation.view)));
    runtime->ui->set_heading(slint::SharedString(presentation.title));
    runtime->ui->set_message(slint::SharedString(presentation.message));
    runtime->ui->set_relying_party_id(
        slint::SharedString(presentation.relyingPartyId)
    );
    runtime->ui->set_interaction_active(!presentation.terminal);
    if(presentation.animation != vauth::client::AnimationKind::none) {
        runtime->ui->set_animation_kind(
            slint::SharedString(animation_name(presentation.animation))
        );
        runtime->ui->set_animation_revision(
            runtime->ui->get_animation_revision() + 1
        );
    }
    if(presentation.view == vauth::client::ViewKind::fingerprint) {
        if(!runtime->renderTimer.running()) {
            auto* runtime_pointer = runtime.get();
            runtime->renderTimer.start(
                slint::TimerMode::Repeated,
                std::chrono::milliseconds(16),
                [runtime_pointer] { runtime_pointer->renderTick(); }
            );
        }
    } else {
        runtime->renderTimer.stop();
    }

    runtime->terminalTimer.stop();
    if(presentation.terminal) {
        const auto display_time =
            presentation.animation == vauth::client::AnimationKind::none
                ? std::chrono::milliseconds(1800)
                : std::chrono::milliseconds(2200);
        runtime->terminalTimer.start(
            slint::TimerMode::SingleShot,
            display_time,
            [runtime_pointer = runtime.get(), revision] {
                if(runtime_pointer->presentationRevision == revision) {
                    runtime_pointer->renderTimer.stop();
                    runtime_pointer->ui->hide();
                }
            }
        );
    }
    runtime->ui->show();
}

void report_ui_error(
    const std::shared_ptr<UiRuntime>& runtime,
    std::string_view message
) {
    ++runtime->presentationRevision;
    runtime->activeRequestId = 0;
    runtime->ui->set_view("status");
    runtime->ui->set_heading("Interaction failed");
    runtime->ui->set_message(slint::SharedString(message));
    runtime->ui->set_interaction_active(false);
    runtime->terminalTimer.start(
        slint::TimerMode::SingleShot,
        std::chrono::milliseconds(1800),
        [
            runtime_pointer = runtime.get(),
            revision = runtime->presentationRevision
        ] {
            if(runtime_pointer->presentationRevision == revision) {
                runtime_pointer->renderTimer.stop();
                runtime_pointer->ui->hide();
            }
        }
    );
}

void cancel_and_report(
    const std::shared_ptr<UiRuntime>& runtime,
    vauth::client::AgentClient& agent,
    std::string_view message
) {
    const uint64_t request_id = runtime->activeRequestId;
    if(request_id != 0) {
        try {
            agent.cancel(request_id);
        } catch(...) {
        }
    }
    report_ui_error(runtime, message);
}

void make_process_undumpable() {
    if(prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
        throw std::runtime_error("Unable to disable vAuth UI core dumps");
}

} // namespace

int main() {
    try {
        make_process_undumpable();

        FingerprintAnimations animations{
            load_animation(vauth::client::animation_data::waiting),
            load_animation(vauth::client::animation_data::success),
            load_animation(vauth::client::animation_data::failure)
        };
        if(!animations.waiting || !animations.success || !animations.failure)
            throw std::runtime_error("Unable to load fingerprint animations");

        auto runtime = std::make_shared<UiRuntime>(AppWindow::create());
        auto startup = std::make_shared<UiStartup>();

        auto agent = std::make_unique<vauth::client::AgentClient>(
            [runtime, startup](vauth::client::InteractionEvent event) {
                {
                    std::lock_guard lock(startup->mutex);
                    if(!startup->eventLoopStarted) {
                        if(startup->events.size() == MAX_STARTUP_EVENTS) {
                            startup->overflowed = true;
                        } else {
                            startup->events.push_back(std::move(event));
                        }
                        startup->eventAvailable.notify_one();
                        return;
                    }
                }
                slint::invoke_from_event_loop(
                    [runtime, event = std::move(event)]() mutable {
                        show_event(runtime, std::move(event));
                    }
                );
            }
        );
        auto* agent_ptr = agent.get();

        runtime->ui->on_approve_presence([runtime, agent_ptr] {
            try {
                agent_ptr->respond_to_presence(
                    runtime->activeRequestId,
                    true
                );
                runtime->ui->set_interaction_active(false);
            } catch(const std::exception& error) {
                cancel_and_report(runtime, *agent_ptr, error.what());
            }
        });
        runtime->ui->on_deny_presence([runtime, agent_ptr] {
            try {
                agent_ptr->respond_to_presence(
                    runtime->activeRequestId,
                    false
                );
                runtime->ui->set_interaction_active(false);
            } catch(const std::exception& error) {
                cancel_and_report(runtime, *agent_ptr, error.what());
            }
        });
        runtime->ui->on_cancel_interaction([runtime, agent_ptr] {
            try {
                agent_ptr->cancel(runtime->activeRequestId);
                runtime->ui->set_interaction_active(false);
            } catch(const std::exception& error) {
                report_ui_error(runtime, error.what());
            }
        });
        runtime->ui->on_submit_password(
            [runtime, agent_ptr](slint::SharedString password) {
                try {
                    runtime->ui->set_password_text("");
                    const std::string_view text(password.data());
                    if(text.size() > MAX_PASSWORD_SIZE)
                        throw std::runtime_error("Password is too long");
                    vauth::uv::SensitiveBytes secret(text.size());
                    std::ranges::copy(text, secret.writable_bytes().begin());
                    agent_ptr->submit_password(
                        runtime->activeRequestId,
                        secret.bytes()
                    );
                    runtime->ui->set_interaction_active(false);
                } catch(const std::exception& error) {
                    cancel_and_report(runtime, *agent_ptr, error.what());
                }
            }
        );

        runtime->ui->window().on_close_requested([runtime, agent_ptr] {
            if(runtime->activeRequestId != 0) {
                try {
                    agent_ptr->cancel(runtime->activeRequestId);
                } catch(...) {
                }
                runtime->activeRequestId = 0;
                runtime->ui->set_interaction_active(false);
            }
            return slint::CloseRequestResponse::HideWindow;
        });

        std::string active_animation_kind;
        int active_animation_revision = -1;
        auto animation_started_at = std::chrono::steady_clock::now();
        bool completion_handled = false;
        runtime->renderTick = [
            runtime_pointer = runtime.get(),
            &animations,
            active_animation_kind = std::move(active_animation_kind),
            active_animation_revision,
            animation_started_at,
            completion_handled
        ]() mutable {
            const std::string requested_kind =
                runtime_pointer->ui->get_animation_kind().data();
            const int requested_revision =
                runtime_pointer->ui->get_animation_revision();
            if(
                requested_kind != active_animation_kind ||
                requested_revision != active_animation_revision
            ) {
                active_animation_kind = requested_kind;
                active_animation_revision = requested_revision;
                animation_started_at = std::chrono::steady_clock::now();
                completion_handled = false;
            }

            auto* animation = animations.for_kind(active_animation_kind);
            const std::size_t total_frames = animation->totalFrame();
            if(total_frames == 0)
                return;

            const auto elapsed = std::chrono::duration<double>(
                std::chrono::steady_clock::now() - animation_started_at
            ).count();
            const std::size_t elapsed_frames = static_cast<std::size_t>(
                elapsed * animation->frameRate()
            );
            const bool loops = active_animation_kind == "waiting";
            const std::size_t frame = loops
                ? elapsed_frames % total_frames
                : std::min(elapsed_frames, total_frames - 1);
            const float scale =
                runtime_pointer->ui->window().scale_factor();
            const std::size_t width = std::max<std::size_t>(
                1,
                static_cast<std::size_t>(
                    ANIMATION_LOGICAL_WIDTH * scale
                )
            );
            const std::size_t height = std::max<std::size_t>(
                1,
                static_cast<std::size_t>(
                    ANIMATION_LOGICAL_HEIGHT * scale
                )
            );
            runtime_pointer->ui->set_lottie_frame(
                render_frame(*animation, frame, width, height)
            );

            if(
                !loops &&
                elapsed_frames >= total_frames &&
                !completion_handled
            ) {
                completion_handled = true;
                if(active_animation_kind == "failure") {
                    runtime_pointer->ui->set_animation_kind("waiting");
                    runtime_pointer->ui->set_animation_revision(
                        runtime_pointer->ui->get_animation_revision() + 1
                    );
                }
            }
        };

        std::cout << "Registered vAuth UI agent generation "
                  << agent->generation() << std::endl;

        // On Wayland, the Slint winit backend must map this component before
        // entering its event loop. Wait without holding up the D-Bus thread,
        // apply the first directed interaction on the UI thread, and let
        // show_event() create the initial window before the loop starts.
        std::deque<vauth::client::InteractionEvent> startup_events;
        {
            std::unique_lock lock(startup->mutex);
            startup->eventAvailable.wait(lock, [startup] {
                return startup->overflowed || !startup->events.empty();
            });
            if(startup->overflowed) {
                throw std::runtime_error(
                    "Too many UI events arrived during startup"
                );
            }
            startup->eventLoopStarted = true;
            startup_events.swap(startup->events);
        }
        for(auto& event : startup_events)
            show_event(runtime, std::move(event));

        slint::run_event_loop(slint::EventLoopMode::RunUntilQuit);
        agent.reset();
        return EXIT_SUCCESS;
    } catch(const std::exception& error) {
        std::cerr << "vauth-ui: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
