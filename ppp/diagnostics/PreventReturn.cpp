#include <ppp/diagnostics/PreventReturn.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/io/File.h>
#include <ppp/cryptography/EVP.h>

/**
 * @file PreventReturn.cpp
 * @brief Implements a cross-platform single-instance guard.
 */

#if !defined(_WIN32)
#include <iostream>
#include <fstream>

#include <fcntl.h>
#include <unistd.h>

#if defined(_LINUX)
#include <sys/file.h>
#endif
#endif

namespace ppp
{
    namespace diagnostics
    {
        /**
         * @brief Transforms an instance name into a stable OS-safe identifier.
         * @param name Raw instance name.
         * @return Namespaced MD5-based identifier, or empty string on failure.
         */
        static ppp::string NameTransform(const char* name) noexcept
        {
            if (NULLPTR == name || *name == '\x0')
            {
                SetLastErrorCode(ErrorCode::PreventReturnNameTransformEmptyInput);
                return ppp::string();
            }

            ppp::string result = ppp::cryptography::ComputeMD5(name, false);
            if (result.empty()) 
            {
                SetLastErrorCode(ErrorCode::CryptoAlgorithmUnsupported);
                return ppp::string();
            }

            result = BOOST_BEAST_VERSION_STRING + ppp::string(".") + result;
            return result;
        }

        PreventReturn::~PreventReturn() noexcept
        {
            Close();
        }

#if defined(_WIN32)
        void PreventReturn::Close() noexcept
        {
            prevent_rerun_.Dispose();
        }

        /**
         * @brief Checks whether a named Windows event already exists.
         * @param name Logical instance name.
         * @return True when another instance holds the same name.
         */
        bool PreventReturn::Exists(const char* name) noexcept
        {
            ppp::string name_string = NameTransform(name);
            if (name_string.empty())
            {
                return false;
            }

            return prevent_rerun_.Exists(name_string.data());
        }

        /**
         * @brief Opens or creates the Windows named event for this instance.
         * @param name Logical instance name.
         * @return True when the event is opened successfully.
         */
        bool PreventReturn::Open(const char* name) noexcept
        {
            ppp::string name_string = NameTransform(name);
            if (name_string.empty())
            {
                SetLastErrorCode(ErrorCode::AppLockAcquireFailed);
                return false;
            }

            try
            {
                prevent_rerun_.Open(name_string.data(), false, false);
                return true;
            }
            catch (const std::exception&)
            {
                SetLastErrorCode(ErrorCode::AppLockAcquireFailed);
                return false;
            }
        }
#else
        // warning: anonymous non-C-compatible type given name for linkage purposes by typedef declaration; add a tag name here [-Wnon-c-typedef-for-linkage]
        // note: type is not C-compatible due to this default member initializer
        // note: type is given name 'FLOCK' for linkage purposes by this typedef declaration
        /**
         * @brief Stores lock-file acquisition state on non-Windows platforms.
         */
        struct FLOCK
        {
            int                                     fd   = -1;
            ppp::string                             path;
            bool                                    open = false;
        };

        /**
         * @brief Attempts to open and exclusively lock the instance PID file.
         * @param name Transformed instance name.
         * @return Lock state containing file descriptor, path, and ownership flag.
         */
        static FLOCK                                FLOCK_OPEN(const char* name) noexcept
        {
            if (NULLPTR == name || *name == '\x0')
            {
                SetLastErrorCode(ErrorCode::PreventReturnNameTransformEmptyInput);
                return { -1, "", false };
            }

            /**
             * @brief Builds platform-specific PID file location.
             */
#if defined(_MACOS)
            ppp::string path = ppp::io::File::GetFullPath(("/tmp/" + ppp::string(name) + ".pid").data());
#else
            ppp::string path = ppp::io::File::GetFullPath(("/var/run/" + ppp::string(name) + ".pid").data());
#endif

            int pid_file = open(path.data(), O_CREAT | O_RDWR, 0666);
            if (pid_file == -1)
            {
                SetLastErrorCode(ErrorCode::AppLockAcquireFailed);
                return { -1, path, false };
            }

            /**
             * @brief Uses a non-blocking exclusive lock to detect existing owner.
             */
            if (flock(pid_file, LOCK_EX | LOCK_NB) < 0)
            {
                int err = errno;
                close(pid_file);

                if (EWOULDBLOCK == err || EAGAIN == err)
                {
                    SetLastErrorCode(ErrorCode::AppAlreadyRunning);
                }
                else
                {
                    SetLastErrorCode(ErrorCode::AppLockAcquireFailed);
                }
                // The lock was not acquired, so .open must be false.
                return { -1, path, false };
            }

            return { pid_file, path, true };
        }

        /**
         * @brief Unlocks and removes a PID file lock.
         * @param path PID file path.
         * @param pid_file Open file descriptor.
         * @return True when lock release and unlink both succeed.
         */
        static bool                                 FLOCK_CLOSE(const char* path, int pid_file) noexcept
        {
            if (NULLPTR == path || *path == '\x0')
            {
                return false;
            }

            if (pid_file == -1)
            {
                return false;
            }

            flock(pid_file, LOCK_UN);
            close(pid_file);

            // unlink() returns 0 on success, -1 on error.
            return unlink(path) == 0;
        }

        void PreventReturn::Close() noexcept
        {
            if (FLOCK_CLOSE(pid_path_.data(), pid_file_))
            {
                pid_file_ = -1;
                pid_path_.clear();
            }
            else if (-1 != pid_file_)
            {
                // Even if unlink failed, the file descriptor is already closed.
                // Reset the internal state to avoid leaking a stale fd.
                SetLastErrorCode(ErrorCode::AppLockReleaseFailed);
                pid_file_ = -1;
                pid_path_.clear();
            }
        }

        /**
         * @brief Checks whether another process already owns the lock.
         * @param name Logical instance name.
         * @return True when the lock appears to be held by another process.
         */
        bool PreventReturn::Exists(const char* name) noexcept
        {
            ppp::string name_string = NameTransform(name);
            if (name_string.empty())
            {
                return false;
            }

            FLOCK f = FLOCK_OPEN(name_string.data());
            if (f.fd == -1)
            {
                // The lock could not be acquired. Check why.
                ErrorCode ec = GetLastErrorCode();
                if (ec == ErrorCode::AppAlreadyRunning)
                {
                    // Another instance holds the lock.
                    return true;
                }
                
                // Any other error (EINVAL, ENOLCK, etc.) means the lock was not taken
                // and there is no evidence of another running instance.
                return false;
            }

            // We successfully got the lock, meaning no other instance was running.
            // Release it immediately and return false.
            FLOCK_CLOSE(f.path.data(), f.fd);
            return false;
        }

        /**
         * @brief Acquires and keeps the process lock for this instance.
         * @param name Logical instance name.
         * @return True when lock acquisition succeeds.
         */
        bool PreventReturn::Open(const char* name) noexcept
        {
            ppp::string name_string = NameTransform(name);
            if (name_string.empty())
            {
                SetLastErrorCode(ErrorCode::AppLockAcquireFailed);
                return false;
            }

            FLOCK f = FLOCK_OPEN(name_string.data());
            if (f.fd == -1)
            {
                if (GetLastErrorCode() == ErrorCode::AppAlreadyRunning)
                {
                    SetLastErrorCode(ErrorCode::AppAlreadyRunning);
                }
                else
                {
                    SetLastErrorCode(ErrorCode::AppLockAcquireFailed);
                }
                return false;
            }

            pid_file_ = f.fd;
            pid_path_ = f.path;
            return true;
        }
#endif
    }
}