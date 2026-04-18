#pragma once

/**
 * @file PreventReturn.h
 * @brief Declares a single-instance guard utility.
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
         * @brief Prevents multiple concurrent instances of the same named process.
         *
         * The implementation uses a named event on Windows and a PID/lock file
         * strategy on non-Windows platforms.
         */
        class PreventReturn final
        {
        public:
            /**
             * @brief Releases any held instance lock resources.
             */
            ~PreventReturn() noexcept;

        public:
            /**
             * @brief Checks whether an instance identified by name already exists.
             * @param name Logical instance name.
             * @return True when the named instance appears to be active.
             */
            bool                    Exists(const char* name) noexcept;

            /**
             * @brief Tries to acquire the single-instance guard for a name.
             * @param name Logical instance name.
             * @return True when the guard is acquired successfully.
             */
            bool                    Open(const char* name) noexcept;

            /**
             * @brief Releases the currently acquired single-instance guard.
             */
            void                    Close() noexcept;

        private:
#if defined(_WIN32)
            ppp::win32::Win32Event  prevent_rerun_;
#else
            int                     pid_file_ = -1;
            ppp::string             pid_path_;
#endif
        };
    }
}
