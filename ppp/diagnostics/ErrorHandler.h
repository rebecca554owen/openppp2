#pragma once

/**
 * @file ErrorHandler.h
 * @brief Declares the singleton ErrorHandler that centralizes thread-local error state
 *        and process-wide error snapshot management.
 *
 * @details
 * Architecture overview:
 * - Each thread maintains its own error state in function-local
 *   `static thread_local` slots (see `ThreadLastErrorCode()` and
 *   `ThreadLastErrorTimestamp()`) so concurrent operations never overwrite each
 *   other's diagnostic state.
 * - When `SetLastErrorCode` is called, the value is also written atomically into
 *   `last_error_code_snapshot_` so that an observer thread can read the most-recently-
 *   seen error across all threads without acquiring any per-thread lock.
 * - Named handlers registered via `RegisterErrorHandler` are invoked synchronously
 *   inside `SetLastErrorCode` on the calling thread without any lock or container copy.
 *   Registration is initialization-only and must complete before multi-thread runtime
 *   startup.
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
         * - `ThreadLastErrorCode()`       — function-local static thread_local per-thread error.
         * - `ThreadLastErrorTimestamp()`  — function-local static thread_local per-thread tick.
         * - Atomic `last_error_code_snapshot_`       — process-wide snapshot, last writer wins.
         * - Atomic `last_error_timestamp_snapshot_`  — timestamp paired with the snapshot.
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
             *  1. Stores `code` into the calling thread's `ThreadLastErrorCode()` slot.
             *  2. Captures the current tick into `ThreadLastErrorTimestamp()`.
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
             * @brief Returns the severity level associated with the given error code.
             * @param code  The error code to classify.
             * @return      The ErrorSeverity value from the X-macro definition, or
             *              ErrorSeverity::kError for any unrecognized code value.
             */
            ErrorSeverity                                                          GetErrorSeverity(ErrorCode code) noexcept;

            /**
             * @brief Returns a short ASCII name for a severity level.
             * @param severity  The severity level to name.
             * @return          "INFO", "WARNING", "ERROR", or "FATAL".
             *                  Returns "UNKNOWN" for values outside the defined range.
             */
            const char*                                                            GetErrorSeverityName(ErrorSeverity severity) noexcept;

            /**
             * @brief Formats a fully-qualified error triplet string.
             * @param code  The error code to format.
             * @return      ppp::string of the form "<uint32_id> <CodeName>: <message>".
             * @note        Numeric ID is the uint32_t cast of the enum value.
             *              Never returns an empty string; falls back to "0 Success: Success"
             *              for the Success code.
             */
            ppp::string                                                            FormatErrorTriplet(ErrorCode code) noexcept;

            /**
             * @brief Tests whether the given error code is fatal (unrecoverable).
             * @param code  The error code to test.
             * @return      true if severity == ErrorSeverity::kFatal, false otherwise.
             */
            bool                                                                   IsErrorFatal(ErrorCode code) noexcept;

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
            /** @brief Returns the calling thread's function-local static error slot. */
            static ErrorCode&                                                       ThreadLastErrorCode() noexcept;
            /** @brief Returns the calling thread's function-local static timestamp slot. */
            static uint64_t&                                                        ThreadLastErrorTimestamp() noexcept;

        private:
            /** @brief Linked-list entry for initialization-time error callback registration. */
            struct ErrorHandlerEntry {
                ppp::string                                                         key;        ///< Unique handler key.
                ppp::function<void(int err)>                                        handler;    ///< Callback target.
            };

        private:
            /** @brief Private constructor — access through `GetDefault()` only. */
            ErrorHandler() noexcept = default;

            /** @brief Copy construction is deleted; the class is a singleton. */
            ErrorHandler(const ErrorHandler&) = delete;
            /** @brief Copy assignment is deleted; the class is a singleton. */
            ErrorHandler& operator=(const ErrorHandler&) = delete;

        private:
            /** @brief Process-wide atomic snapshot of the latest error code (last writer wins). */
            std::atomic<uint32_t>                                                  last_error_code_snapshot_{static_cast<uint32_t>(ErrorCode::Success)};
            /** @brief Process-wide atomic timestamp paired with `last_error_code_snapshot_`. */
            std::atomic<uint64_t>                                                  last_error_timestamp_snapshot_{0};

            /** @brief Linked-list of named callbacks; registration is initialization-only. */
            ppp::list<ErrorHandlerEntry>                                           error_handlers_;
        };
    }
}
