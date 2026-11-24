#pragma once

/**
 * @file AsioCompat.h
 * @brief 与 Boost 版本无关的 asio 调用封装。
 * @author("OPENPPP2 Team")
 * @license("GPL-3.0")
 *
 * @note 本头文件刻意保持轻量：它只依赖 Boost 的两个头，不引入项目的
 *       预编译头，因为 include 边界检查会统计 ppp 目录下提到预编译头的
 *       头文件数量并要求其不增长。
 */

#include <boost/version.hpp>
#include <boost/system/error_code.hpp>

namespace ppp {
    namespace asio_compat {
        /**
         * @brief 取消一个等待式计时器上的挂起操作。
         *
         * @details Boost 1.87 起 basic_waitable_timer 不再提供接受 error_code 的
         *          cancel() 重载，只剩下会抛异常的版本。旧版走原重载，新版走无参
         *          版本并吞掉异常，于是"取消失败"不再通过 error_code 上报。
         *
         *          调用方原本就只用它来打断挂起的等待，并不检查 error_code，
         *          所以这个差异不影响行为；保留 error_code 参数是为了让调用点
         *          在两个 Boost 版本上都能编译。
         *
         * @param timer 计时器。
         * @param ec 接收操作结果；新版下总是被清成 success。
         */
        template <class Timer>
        inline void CancelTimer(Timer& timer, boost::system::error_code& ec) noexcept {
#if BOOST_VERSION >= 108700
            try {
                timer.cancel();
            }
            catch (...) {
            }
            ec.clear();
#else
            timer.cancel(ec);
#endif
        }
    }
}
