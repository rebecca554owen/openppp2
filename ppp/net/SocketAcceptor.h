#pragma once

#include <ppp/stdafx.h>

/**
 * @file SocketAcceptor.h
 * @brief Declares the platform-abstracted socket acceptor interface.
 */

namespace ppp 
{
    namespace net 
    {
        /**
         * @brief Abstract listener interface that accepts inbound socket handles.
         */
        class SocketAcceptor : public std::enable_shared_from_this<SocketAcceptor>
        {
        public:
            /**
             * @brief Event payload for an accepted native socket descriptor.
             */
            struct                                                                  AcceptSocketEventArgs
            {
                /** @brief Accepted native socket handle; -1 indicates invalid. */
                int                                                                 Socket = -1;
            };
            /** @brief Delegate type invoked when a socket is accepted. */
            typedef ppp::function<void(SocketAcceptor*, AcceptSocketEventArgs&)>    AcceptSocketEventHandler;

        public:
            /** @brief Callback invoked after accepting a new client socket. */
            AcceptSocketEventHandler                                                AcceptSocket;

        public:
            /** @brief Virtual destructor for interface-safe cleanup. */
            virtual ~SocketAcceptor() noexcept = default;

        public:
            /** @brief Gets the native listener socket handle. */
            virtual int                                                             GetHandle() noexcept = 0;
            /** @brief Indicates whether the acceptor is currently open. */
            virtual bool                                                            IsOpen() noexcept = 0;
            /** @brief Opens and starts listening on the specified local endpoint. */
            virtual bool                                                            Open(const char* localIP, int localPort, int backlog) noexcept = 0;
            /** @brief Releases listener resources and stops accepting. */
            virtual void                                                            Dispose() noexcept = 0;
            /** @brief Dispatches accepted-socket event or closes unhandled socket. */
            virtual void                                                            OnAcceptSocket(AcceptSocketEventArgs& e) noexcept;

        public:
            /** @brief Creates a platform-specific acceptor implementation instance. */
            static std::shared_ptr<SocketAcceptor>                                  New() noexcept;
        };
    }
}
