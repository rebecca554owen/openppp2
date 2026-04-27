#include <ppp/net/SocketAcceptor.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Socket.h>

/**
 * @file SocketAcceptor.cpp
 * @brief Implements platform selection and event dispatch for socket acceptors.
 */

#if defined(_WIN32)
#include <windows/ppp/net/Win32SocketAcceptor.h>
#else
#include <common/unix/net/UnixSocketAcceptor.h>
#endif

namespace ppp
{
    namespace net
    {
        /**
         * @brief Dispatches accepted-socket callback and enforces fallback close behavior.
         * @param e Accepted socket event arguments.
         */
        void SocketAcceptor::OnAcceptSocket(AcceptSocketEventArgs& e) noexcept
        {
            AcceptSocketEventHandler eh = AcceptSocket;
            if (eh)
            {
                eh(this, e);
            }
            else
            {
                /**
                 * @brief Ensures accepted sockets are not leaked when no handler is registered.
                 */
                Socket::Closesocket(e.Socket);
            }
        }

        /**
         * @brief Creates the OS-specific socket acceptor implementation.
         * @return Shared pointer to the concrete acceptor object.
         */
        std::shared_ptr<SocketAcceptor> SocketAcceptor::New() noexcept
        {
#if defined(_WIN32)
            return make_shared_object<ppp::net::Win32SocketAcceptor>();
#else
            return make_shared_object<ppp::net::UnixSocketAcceptor>();
#endif
        }
    }
}
