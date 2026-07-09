#include <windows/ppp/win32/Win32Event.h>

#include <iostream>
#include <exception>
#include <string>

#include <ppp/diagnostics/Error.h>

#include <Windows.h>

namespace ppp
{
    namespace win32
    {
        Win32Event::Win32Event() noexcept
            : hKrlEvt(NULLPTR)
        {

        }

        Win32Event::Win32Event(const ppp::string& name, bool initialState, bool openOrCreate) noexcept
            : Win32Event()
        {
            OpenKernelEventObject(name, initialState, openOrCreate);
        }

        void Win32Event::Open(const ppp::string& name, bool initialState, bool openOrCreate)
        {
            int err = OpenKernelEventObject(name, initialState, openOrCreate);
            if (err < 0)
            {
                throw std::invalid_argument(name.data());
            }
            elif (err > 0)
            {
                throw std::runtime_error("Cannot create or open kernel event synchronization object. It may be because the event name has been used or the name string is incorrect.");
            }
        }

        int Win32Event::OpenKernelEventObject(const ppp::string& name, bool initialState, bool openOrCreate) noexcept
        {
            HANDLE h = hKrlEvt.exchange(NULLPTR);
            if (NULLPTR != h)
            {
                CloseHandle(h);
            }

            if (name.empty())
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32EventOpenKernelEventNameEmpty);
                return -1;
            }

            HANDLE existing = OpenEventA(EVENT_ALL_ACCESS, FALSE, name.c_str());
            if (NULLPTR != existing)
            {
                if (openOrCreate)
                {
                    // Open-only mode: attaching to an already-published event is the success case.
                    hKrlEvt = existing;
                    return 0;
                }

                // Create/acquire mode (single-instance guard): the named object already exists,
                // which means another instance currently owns the guard. Do NOT adopt its handle
                // as if we were the owner - that was the historical bug that let a second instance
                // believe it acquired the lock. Report contention instead.
                CloseHandle(existing);
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32EventCreateFailed);
                return 1;
            }

            if (openOrCreate)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32EventOpenFailed);
                return -1;
            }

            HANDLE created = CreateEventA(NULLPTR, initialState ? FALSE : TRUE, initialState ? TRUE : FALSE, name.c_str());
            if (NULLPTR != created)
            {
                // CreateEventA returns a valid handle to a pre-existing object and sets
                // ERROR_ALREADY_EXISTS. This closes the OpenEventA->CreateEventA race window:
                // if another acquirer created the guard meanwhile, we are not the owner.
                if (ERROR_ALREADY_EXISTS == GetLastError())
                {
                    CloseHandle(created);
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32EventCreateFailed);
                    return 1;
                }

                hKrlEvt = created;
                return 0;
            }

            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32EventCreateFailed);
            return 1;
        }

        Win32Event::~Win32Event() noexcept
        {
            Dispose();
        }

        void Win32Event::Dispose() noexcept
        {
            HANDLE h = hKrlEvt.exchange(NULLPTR);
            if (NULLPTR != h)
            {
                CloseHandle(h);
            }
        }

        bool Win32Event::WaitOne(int millisecondsTimeout) noexcept
        {
            HANDLE h = hKrlEvt.load();
            if (NULLPTR == h)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
                return false;
            }

            DWORD wait_result = WaitForSingleObject(hKrlEvt, millisecondsTimeout);
            if (WAIT_OBJECT_0 == wait_result)
            {
                return true;
            }
            elif (WAIT_TIMEOUT == wait_result)
            {
                return false;
            }

            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ThreadSyncConditionWaitFailed);
            return false;
        }

        bool Win32Event::WaitOne() noexcept
        {
            return WaitOne(INFINITE);
        }

        bool Win32Event::Set() noexcept
        {
            HANDLE h = hKrlEvt.load();
            if (NULLPTR == h)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
                return false;
            }

            if (SetEvent(h))
            {
                return true;
            }

            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32EventSetFailed);
            return false;
        }

        bool Win32Event::Reset() noexcept
        {
            HANDLE h = hKrlEvt.load();
            if (NULLPTR == h)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
                return false;
            }

            if (ResetEvent(h))
            {
                return true;
            }

            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32EventResetFailed);
            return false;
        }

        bool Win32Event::IsValid() noexcept
        {
            HANDLE h = hKrlEvt.load();
            return NULLPTR != h;
        }

        bool Win32Event::Exists(const ppp::string& name) noexcept
        {
            HANDLE hEvt = OpenEventA(EVENT_ALL_ACCESS, FALSE, name.c_str());
            if (NULLPTR == hEvt)
            {
                return false;
            }

            CloseHandle(hEvt);
            return true;
        }
    }
}
