#pragma once

/**
 * @file ErrorHandler.h
 * @brief Declares the singleton ErrorHandler that centralizes thread-local error state
 *        and process-wide error snapshot management.
 *
 * @details
 * Architecture overview:
 * - Each thread maintains its own `tls_last_error_code_` (thread_local) and
 *   `tls_last_error_timestamp_` so that concurrent operations never overwrite each
 *   other's diagnostic state.
 * - When `SetLastErrorCode` is called, the value is also written atomically into
 *   `last_error_code_snapshot_` so that an observer thread can read the most-recently-
 *   seen error across all threads without acquiring any per-thread lock.
 * - Named handlers registered via `RegisterErrorHandler` are invoked synchronously
 *   inside `SetLastErrorCode` on the calling thread.  Registration itself is
 *   serialized by `error_handlers_sync_`, but handler invocations are NOT protected —
 *   registered handlers must be internally thread-safe if accessed from multiple threads.
 *
 * @note  The singleton returned by `GetDefault()` is the single source of truth for
 *        all free functions declared in Error.h (`GetLastErrorCode`, `SetLastErrorCode`,
 *        etc.), which simply delegate to this object.
 * @note  Handler registration (`RegisterErrorHandler`) is NOT thread-safe and must
 *        be completed before the multi-thread runtime is started.
 */

#include <ppp/diagnostics/Error.h>
#include <atomic>

namespace ppp {
    namespace diagnostics {
        /**
         * @brief Singleton service that stores and dispatches diagnostic error codes.
         *
         * @details
         * Storage model:
         * - Thread-local `tls_last_error_code_`       — per-thread last error code.
         * - Thread-local `tls_last_error_timestamp_`  — tick count when the error was set.
         * - Atomic `last_error_code_snapshot_`        — process-wide snapshot, last writer wins.
         * - Atomic `last_error_timestamp_snapshot_`   — timestamp paired with the snapshot.
         *
         * @note  Copy construction and copy assignment are deleted; obtain the instance
         *        exclusively through `GetDefault()`.
         */
        class ErrorHandler final {
        public:
            /**
             * @brief Returns the process-wide singleton instance.
             * @return Reference to the sole ErrorHandler object.
             * @note  Thread-safe after first call (Meyers singleton guarantee).
             */
            static ErrorHandler&                                                   GetDefault() noexcept;

        public:
            /**
             * @brief Retrieves the calling thread's last error code.
             * @return Thread-local error code set by the most recent `SetLastErrorCode` on
             *         this thread, or `ErrorCode::Success` if none has been set yet.
             * @note  Thread-safe; reads only thread-local storage — no synchronization needed.
             */
            ErrorCode                                                              GetLastErrorCode() noexcept;

            /**
             * @brief Retrieves the process-wide error code snapshot.
             * @return The atomically stored error code from the most recent `SetLastErrorCode`
             *         call across all threads (last writer wins).
             * @note  May differ from the calling thread's own thread-local value.
             */
            ErrorCode                                                              GetLastErrorCodeSnapshot() noexcept;

            /**
             * @brief Retrieves the tick timestamp of the most recent process-wide error update.
             * @return Tick count (platform-defined unit) when `last_error_code_snapshot_`
             *         was last written; zero if no error has been set since startup.
             */
            uint64_t                                                               GetLastErrorTimestamp() noexcept;

            /**
             * @brief Records an error code for the current thread and notifies all observers.
             *
             * @details The implementation:
             *  1. Stores `code` into the calling thread's `tls_last_error_code_`.
             *  2. Captures the current tick into `tls_last_error_timestamp_`.
             *  3. Atomically updates `last_error_code_snapshot_` and
             *     `last_error_timestamp_snapshot_` (visible to all threads).
             *  4. Iterates `error_handlers_` and calls each handler with the raw int
             *     representation of `code`.
             *
             * @param code Error code to record.
             * @return The same `code` value that was provided.
             * @note  Handlers are called synchronously on the caller's thread.
             *        They must not call `SetLastErrorCode` recursively.
             */
            ErrorCode                                                              SetLastErrorCode(ErrorCode code) noexcept;

            /**
             * @brief Converts an error code to a human-readable static message.
             * @param code Error code to format.
             * @return Null-terminated ASCII string describing the error.
             *         The lifetime of the returned pointer is that of the process.
             */
            const char*                                                            FormatErrorString(ErrorCode code) noexcept;

            /**
             * @brief Registers or removes a named error notification callback.
             * @param key     Unique string key identifying the handler entry.
             *                Providing an empty or null-target handler with an existing key
             *                effectively removes the prior registration.
             * @param handler Callable receiving the raw `int` representation of each
             *                subsequent error code passed to `SetLastErrorCode`.
             * @warning NOT thread-safe.  Must be called exclusively before starting
             *          the multi-thread runtime.  Modifying handlers at runtime may
             *          cause data races.
             */
            void                                                                   RegisterErrorHandler(const ppp::string& key, const ppp::function<void(int err)>& handler) noexcept;

        private:
            /** @brief Private constructor — access through `GetDefault()` only. */
            ErrorHandler() noexcept = default;

            /** @brief Copy construction is deleted; the class is a singleton. */
            ErrorHandler(const ErrorHandler&) = delete;
            /** @brief Copy assignment is deleted; the class is a singleton. */
            ErrorHandler& operator=(const ErrorHandler&) = delete;

        private:
            /** @brief Per-thread last error code; default-initialized to `ErrorCode::Success`. */
            static thread_local ErrorCode                                          tls_last_error_code_;
            /** @brief Per-thread tick timestamp of the most recent error; zero until first set. */
            static thread_local uint64_t                                           tls_last_error_timestamp_;

            /** @brief Process-wide atomic snapshot of the latest error code (last writer wins). */
            std::atomic<uint32_t>                                                  last_error_code_snapshot_{static_cast<uint32_t>(ErrorCode::Success)};
            /** @brief Process-wide atomic timestamp paired with `last_error_code_snapshot_`. */
            std::atomic<uint64_t>                                                  last_error_timestamp_snapshot_{0};

            /** @brief Mutex that serializes modifications to `error_handlers_`. */
            std::mutex                                                             error_handlers_sync_;
            /** @brief Map of named error callbacks; key is caller-supplied identifier. */
            ppp::unordered_map<ppp::string, ppp::function<void(int err)>>          error_handlers_;
        };
    }
}
