// Link-only stubs for spinlock_test.
//
// SpinLock.cpp needs ppp::GetCurrentThreadId() (normally in ppp/stdafx.cpp,
// which would drag the io/File/Random dependency graph into this test) and
// ErrorHandler::SetLastErrorCode() needs Executors::GetTickCount().

#include <ppp/stdafx.h>
#include <ppp/threading/Executors.h>

#if defined(__APPLE__)
#include <pthread.h>
#else
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace ppp {

    int64_t GetCurrentThreadId() noexcept {
#if defined(__APPLE__)
        uint64_t tid = 0;
        pthread_threadid_np(nullptr, &tid);
        return static_cast<int64_t>(tid);
#else
        return static_cast<int64_t>(::syscall(SYS_gettid));
#endif
    }

    uint64_t GetTickCount() noexcept {
        return 0;
    }

namespace threading {

    uint64_t Executors::GetTickCount() noexcept {
        return 0;
    }

}  // namespace threading
}  // namespace ppp
