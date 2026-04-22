#pragma once

#include <ppp/stdafx.h>

/**
 * @file SocketAcceptor.h
 * @brief Declares the platform-abstracted socket acceptor interface.
 *
 * @ref ppp::net::SocketAcceptor provides a uniform virtual interface for
 * listening on a TCP port and dispatching native socket handles to the rest
 * of the VPN/SD-WAN stack without exposing Boost.Asio types.
 *
 * Design notes:
 * - The concrete implementation returned by @ref SocketAcceptor::New() is
 *   platform-specific (Windows IOCP, Linux epoll, etc.) but exposes an
 *   identical API.
 * - Once @ref Open is called successfully, every accepted connection fires
 *   the @ref AcceptSocket event with a populated @ref AcceptSocketEventArgs.
 *   The event handler is responsible for either taking ownership of the
 *   descriptor or closing it.
 * - Calling @ref Dispose stops the listener and releases all OS resources.
 *   After @ref Dispose returns, no further events are delivered.
 */

namespace ppp 
{
    namespace net 
    {
        /**
         * @brief Abstract listener interface that accepts inbound socket handles.
         *
         * Derived classes implement the platform-specific accept loop.  Callers
         * obtain a platform-specific instance via @ref New() and interact with it
         * exclusively through this interface.
         *
         * Typical usage:
         * @code
         *   auto acceptor = ppp::net::SocketAcceptor::New();
         *   acceptor->AcceptSocket = [](SocketAcceptor*, AcceptSocketEventArgs& e) {
         *       // take ownership of e.Socket or close it
         *   };
         *   acceptor->Open("0.0.0.0", 8080, 128);
         * @endcode
         */
        class SocketAcceptor : public std::enable_shared_from_this<SocketAcceptor>
        {
        public:
            /**
             * @brief Event payload for an accepted native socket descriptor.
             *
             * Structure layout:
             *   Socket = int,  ///< Native socket handle; -1 if invalid
             */
            struct                                                                  AcceptSocketEventArgs
            {
                /**
                 * @brief Accepted native socket handle.
                 *
                 * Set to the handle of the newly accepted client connection.
                 * A value of -1 signals that no valid socket was produced.
                 * The event handler must either adopt the descriptor (and close
                 * it eventually) or close it immediately if it is not needed.
                 */
                int                                                                 Socket = -1;
            };

            /**
             * @brief Delegate type invoked when a socket is accepted.
             *
             * @param self  Pointer to the acceptor that fired the event.
             * @param e     Mutable event arguments containing the new socket handle.
             */
            typedef ppp::function<void(SocketAcceptor*, AcceptSocketEventArgs&)>    AcceptSocketEventHandler;

        public:
            /**
             * @brief Callback invoked after accepting a new client socket.
             *
             * Assign this member before calling @ref Open.  If left null, the
             * default @ref OnAcceptSocket implementation closes the descriptor.
             */
            AcceptSocketEventHandler                                                AcceptSocket;

        public:
            /**
             * @brief Virtual destructor for interface-safe cleanup.
             *
             * Concrete implementations must release all OS-level listener resources
             * in their own destructors.  The base destructor is intentionally empty.
             */
            virtual ~SocketAcceptor() noexcept = default;

        public:
            /**
             * @brief Gets the native listener socket handle.
             * @return  Native descriptor of the listening socket, or -1 when not open.
             */
            virtual int                                                             GetHandle() noexcept = 0;

            /**
             * @brief Indicates whether the acceptor is currently open and listening.
             * @return  true after a successful @ref Open call and before @ref Dispose.
             */
            virtual bool                                                            IsOpen() noexcept = 0;

            /**
             * @brief Opens and starts listening on the specified local endpoint.
             * @param localIP    Textual IPv4/IPv6 address to bind (e.g. "0.0.0.0").
             * @param localPort  Local port to listen on; must be in [1, 65535].
             * @param backlog    Maximum length of the pending-connection queue.
             * @return           true on success; false if bind or listen fails.
             * @note             Implementation must set SO_REUSEADDR before binding.
             */
            virtual bool                                                            Open(const char* localIP, int localPort, int backlog) noexcept = 0;

            /**
             * @brief Releases listener resources and stops accepting new connections.
             *
             * After this call @ref IsOpen returns false.  Any in-flight accept
             * completions are cancelled.  Already-accepted descriptors are unaffected.
             */
            virtual void                                                            Dispose() noexcept = 0;

            /**
             * @brief Dispatches accepted-socket event or closes unhandled socket.
             *
             * Default implementation: if @ref AcceptSocket is set, invokes it with
             * @p e; otherwise closes @p e.Socket to prevent descriptor leak.
             *
             * @param e  Mutable event arguments containing the new socket handle.
             */
            virtual void                                                            OnAcceptSocket(AcceptSocketEventArgs& e) noexcept;

        public:
            /**
             * @brief Creates a platform-specific acceptor implementation instance.
             * @return  Shared pointer to a newly constructed concrete @ref SocketAcceptor;
             *          NULLPTR if allocation fails.
             * @note    The returned object is idle until @ref Open is called.
             */
            static std::shared_ptr<SocketAcceptor>                                  New() noexcept;
        };
    }
}
