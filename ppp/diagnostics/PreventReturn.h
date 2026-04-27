#pragma once

/**
 * @file PreventReturn.h
 * @brief Declares a single-instance guard that prevents more than one copy of the
 *        process from running simultaneously under the same logical name.
 *
 * @details
 * `PreventReturn` implements the classic "single-instance application" pattern:
 *
 *  - **Windows**: Uses a named `Win32Event` kernel object.  `Open()` creates the event
 *    with a unique name; `Exists()` checks whether the event already exists in the kernel
 *    namespace.  The event is released in the destructor or by calling `Close()`.
 *
 *  - **POSIX (Linux, macOS, Android)**: Uses a PID lock-file strategy.  `Open()` creates
 *    (or truncates) a file at `pid_path_`, writes the current PID, and acquires an
 *    exclusive advisory lock (`flock`/`fcntl`).  `Exists()` checks whether a lock-file
 *    exists and whether the recorded PID is still alive.  `Close()` releases the lock and
 *    removes the file.
 *
 * ### Typical usage
 * ```cpp
 * ppp::diagnostics::PreventReturn guard;
 * if (guard.Exists("my-service")) {
 *     // Another instance is already running — exit early.
 *     return 1;
 * }
 * if (!guard.Open("my-service")) {
 *     // Could not acquire the lock — treat as a fatal error.
 *     return 1;
 * }
 * // ... run the service ...
 * // guard.Close() is called automatically by the destructor.
 * ```
 *
 * @note  `PreventReturn` is not copyable or movable.
 * @note  On Windows, `name` is used verbatim as the kernel event name; it must not
 *        contain characters that are illegal in kernel object names (e.g. backslash is
 *        interpreted as a namespace separator).
 * @note  On POSIX, `name` is used as part of the lock-file path; it should not contain
 *        path separators unless an absolute path is intended.
 */

#include <ppp/stdafx.h>

#if defined(_WIN32)
#include <windows/ppp/win32/Win32Event.h>
#endif

namespace ppp 
{
    namespace diagnostics 
    {
        /**
         * @brief Single-instance application guard.
         *
         * @details
         * Prevents multiple concurrent instances of the same named process from running.
         * The implementation uses a named kernel event on Windows and a PID/advisory-lock
         * file strategy on POSIX platforms.
         *
         * The guard is acquired by calling `Open()` and released either explicitly via
         * `Close()` or automatically when the destructor runs.
         *
         * @note  All public methods are `noexcept`.
         */
        class PreventReturn final
        {
        public:
            /**
             * @brief Destructor — releases any held instance lock resources.
             * @details Equivalent to calling `Close()`.  Safe to call even when no lock
             *          has been acquired.
             */
            ~PreventReturn() noexcept;

        public:
            /**
             * @brief Checks whether a named instance guard already exists.
             * @param name Logical instance name used to identify the guard.
             *             On Windows this is a kernel object name; on POSIX it is used to
             *             derive a lock-file path.
             * @return true  when a guard with the same name appears to be active (another
             *               instance is running).
             * @return false when no active guard was detected.
             * @note  This method does NOT acquire the guard itself — it is a non-destructive
             *        probe.  Call `Open()` separately if you need to own the guard.
             */
            bool                    Exists(const char* name) noexcept;

            /**
             * @brief Attempts to acquire the single-instance guard for the given name.
             * @param name Logical instance name.  Must match the name used with `Exists()`.
             * @return true  when the guard was acquired successfully; this process is now
             *               the sole owner for `name`.
             * @return false when the guard could not be acquired (another owner exists or an
             *               OS-level error occurred).
             * @note  Calling `Open()` when a guard is already held by this object first
             *        releases the existing guard before attempting to acquire the new one.
             */
            bool                    Open(const char* name) noexcept;

            /**
             * @brief Releases the currently held single-instance guard.
             * @details On Windows, closes the kernel event handle.  On POSIX, releases the
             *          advisory file lock and removes the lock file.  Safe to call multiple
             *          times or when no guard is held.
             */
            void                    Close() noexcept;

        private:
#if defined(_WIN32)
            /** @brief Named kernel event used as the single-instance lock on Windows. */
            ppp::win32::Win32Event  prevent_rerun_;
#else
            /** @brief File descriptor of the PID lock file; -1 when no lock is held. */
            int                     pid_file_ = -1;
            /** @brief Absolute path to the PID lock file on POSIX platforms. */
            ppp::string             pid_path_;
#endif
        };
    }
}
