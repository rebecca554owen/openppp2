#pragma once

#include <ppp/app/runtime/RuntimeReadiness.h>
#include <ppp/app/runtime/RuntimeSnapshotPublisher.h>
#include <ppp/app/runtime/RuntimeStopCoordinator.h>

#include <algorithm>
#include <cstdint>
#include <mutex>
#include <utility>

namespace ppp::app::runtime {

class RuntimeLifecycle final {
public:
    using Listener = RuntimeSnapshotPublisher::Listener;

    std::uint64_t Begin(RuntimeSnapshot seed, std::uint64_t now) noexcept {
        RuntimeSnapshot snapshot;
        {
            std::lock_guard<std::mutex> scope(mutex_);
            const std::uint64_t generation = ++generation_;
            stop_coordinator_.BeginGeneration(generation);
            readiness_ = RuntimeReadiness();
            requested_phase_ = RuntimePhase::Starting;

            snapshot = std::move(seed);
            snapshot.generation = generation;
            snapshot.monotonic_ms = NextTimestamp(now);
            snapshot.phase = RuntimePhase::Starting;
            current_ = snapshot;
        }
        publisher_.Publish(snapshot);
        return snapshot.generation;
    }

    bool Transition(
        std::uint64_t generation,
        RuntimePhase phase,
        std::uint64_t now) noexcept {
        RuntimeSnapshot snapshot;
        {
            std::lock_guard<std::mutex> scope(mutex_);
            if (generation == 0 || generation != generation_) {
                return false;
            }
            requested_phase_ = phase;
            current_.phase = GateConnectedPhase(phase, readiness_);
            current_.monotonic_ms = NextTimestamp(now);
            snapshot = current_;
        }
        return publisher_.Publish(std::move(snapshot));
    }

    bool UpdateReadiness(
        std::uint64_t generation,
        RuntimeReadiness readiness,
        std::uint64_t now) noexcept {
        RuntimeSnapshot snapshot;
        {
            std::lock_guard<std::mutex> scope(mutex_);
            if (generation == 0 || generation != generation_) {
                return false;
            }
            readiness_ = readiness;
            if (requested_phase_ == RuntimePhase::Connected &&
                current_.phase != RuntimePhase::Stopping &&
                current_.phase != RuntimePhase::Idle &&
                current_.phase != RuntimePhase::Failed) {
                current_.phase = GateConnectedPhase(requested_phase_, readiness_);
            }
            current_.monotonic_ms = NextTimestamp(now);
            snapshot = current_;
        }
        return publisher_.Publish(std::move(snapshot));
    }

    bool TryBeginStop(std::uint64_t generation, std::uint64_t now) noexcept {
        RuntimeSnapshot snapshot;
        {
            std::lock_guard<std::mutex> scope(mutex_);
            if (generation == 0 || generation != generation_ ||
                !stop_coordinator_.TryBeginStop(generation)) {
                return false;
            }
            requested_phase_ = RuntimePhase::Stopping;
            current_.phase = RuntimePhase::Stopping;
            current_.monotonic_ms = NextTimestamp(now);
            snapshot = current_;
        }
        return publisher_.Publish(std::move(snapshot));
    }

    bool CompleteStop(
        std::uint64_t generation,
        bool success,
        RuntimeError error,
        std::uint64_t now) noexcept {
        RuntimeSnapshot snapshot;
        {
            std::lock_guard<std::mutex> scope(mutex_);
            if (generation == 0 || generation != generation_ ||
                !stop_coordinator_.IsStopping(generation)) {
                return false;
            }
            stop_coordinator_.CompleteStop(generation, success);
            requested_phase_ = success ? RuntimePhase::Idle : RuntimePhase::Failed;
            current_.phase = requested_phase_;
            current_.last_error = success ? RuntimeError() : std::move(error);
            current_.monotonic_ms = NextTimestamp(now);
            snapshot = current_;
        }
        return publisher_.Publish(std::move(snapshot));
    }

    RuntimeSnapshot GetSnapshot() const noexcept {
        return publisher_.GetLatest();
    }

    std::uint64_t Subscribe(Listener listener) noexcept {
        return publisher_.Subscribe(std::move(listener));
    }

    void Unsubscribe(std::uint64_t token) noexcept {
        publisher_.Unsubscribe(token);
    }

private:
    std::uint64_t NextTimestamp(std::uint64_t now) noexcept {
        const std::uint64_t minimum = current_.monotonic_ms + 1;
        return std::max(now, minimum);
    }

    mutable std::mutex mutex_;
    RuntimeSnapshotPublisher publisher_;
    RuntimeStopCoordinator stop_coordinator_;
    RuntimeSnapshot current_;
    RuntimeReadiness readiness_;
    RuntimePhase requested_phase_ = RuntimePhase::Idle;
    std::uint64_t generation_ = 0;
};

}
