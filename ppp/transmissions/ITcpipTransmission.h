#pragma once

/**
 * @file ITcpipTransmission.h
 * @brief Declares the TCP/IP-based transmission implementation.
 */

#include <ppp/transmissions/ITransmission.h>

#if defined(_WIN32)
#include <windows/ppp/net/QoSS.h>
#endif

namespace ppp {
    namespace transmissions {
        /**
         * @brief Implements transmission I/O over a Boost.Asio TCP socket.
         */
        class ITcpipTransmission : public ITransmission {
            /** @brief Grants QoS helper direct access to transport internals. */
            friend class                                                                        ITransmissionQoS;

        public:
            /**
             * @brief Initializes a TCP/IP transmission instance.
             * @param context Shared io_context for async operations.
             * @param strand Shared strand for serialized callbacks.
             * @param socket Connected TCP socket.
             * @param configuration Application transmission configuration.
             */
            ITcpipTransmission(
                const ContextPtr&                                                               context, 
                const StrandPtr&                                                                strand,
                const std::shared_ptr<boost::asio::ip::tcp::socket>&                            socket, 
                const AppConfigurationPtr&                                                      configuration) noexcept;
            /** @brief Releases transmission resources. */
            virtual ~ITcpipTransmission()                                                                      noexcept;

        public:
            /** @brief Disposes socket state and base transmission resources. */
            virtual void                                                                        Dispose() noexcept override;
            /** @brief Returns the cached remote TCP endpoint. */
            virtual boost::asio::ip::tcp::endpoint                                              GetRemoteEndPoint() noexcept override;
            /**
             * @brief Reads an exact number of bytes from the socket.
             * @param y Coroutine yield context.
             * @param length Requested number of bytes.
             * @return Byte buffer on success; null on failure.
             */
            virtual std::shared_ptr<Byte>                                                       ReadBytes(YieldContext& y, int length) noexcept;

        protected:
            /**
             * @brief Reads bytes through the QoS-aware read path.
             * @param y Coroutine yield context.
             * @param length Requested number of bytes.
             * @return Byte buffer on success; null on failure.
             */
            virtual std::shared_ptr<Byte>                                                       DoReadBytes(YieldContext& y, int length) noexcept;
            /**
             * @brief Asynchronously writes a byte range to the socket.
             * @param packet Buffer that owns payload memory.
             * @param offset Start offset in @p packet.
             * @param packet_length Number of bytes to write.
             * @param cb Completion callback receiving success state.
             * @return true if write is scheduled; otherwise false.
             */
            virtual bool                                                                        DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept;
        
        private:
            /** @brief Performs one-time cleanup of socket-related resources. */
            void                                                                                Finalize() noexcept;
            /** @brief Migrates the socket to the scheduler selected by Executors. */
            virtual bool                                                                        ShiftToScheduler() noexcept override;

        private:
#if defined(_WIN32)
            /** @brief Optional Windows QoS wrapper for socket traffic classification. */
            std::shared_ptr<ppp::net::QoSS>                                                     qoss_;
#endif
            /** @brief Indicates whether this transmission has been disposed. */
            bool                                                                                disposed_ = false;
            /** @brief Owned connected TCP socket. */
            std::shared_ptr<boost::asio::ip::tcp::socket>                                       socket_;
            /** @brief Cached peer endpoint captured at construction. */
            boost::asio::ip::tcp::endpoint                                                      remoteEP_;
        };
    }
}
