// ITransmission.h
#pragma once

// Project precompiled header and core dependencies
#include <ppp/stdafx.h>
#include <ppp/Int128.h>
#include <ppp/cryptography/Ciphertext.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>
#include <ppp/transmissions/ITransmissionQoS.h>
#include <ppp/transmissions/ITransmissionStatistics.h>

namespace ppp {
    namespace transmissions {

        // Core transmission interface providing encrypted, handshaked, coroutine‑aware I/O.
        class ITransmission : public ppp::net::asio::IAsynchronousWriteIoQueue {
            // Bridge class (defined in .cpp) accesses private state for static helpers.
            friend class ITransmissionBridge;
            // QoS manager needs internal access for priority and rate limiting.
            friend class ITransmissionQoS;

            // Boost deadline timer for handshake timeouts.
            typedef boost::asio::deadline_timer                                                     DeadlineTimer;
            typedef std::shared_ptr<DeadlineTimer>                                                  DeadlineTimerPtr;

        public:
            // Public type aliases for configuration, cipher, coroutine context, etc.
            typedef ppp::configurations::AppConfiguration                                           AppConfiguration;
            typedef std::shared_ptr<AppConfiguration>                                               AppConfigurationPtr;
            typedef ppp::cryptography::Ciphertext                                                   Ciphertext;
            typedef std::shared_ptr<Ciphertext>                                                     CiphertextPtr;
            typedef ppp::coroutines::YieldContext                                                   YieldContext;
            typedef std::shared_ptr<boost::asio::io_context>                                        ContextPtr;
            typedef std::shared_ptr<boost::asio::strand<boost::asio::io_context::executor_type>>    StrandPtr;
            typedef ppp::function<void(bool)>                                                       AsynchronousWriteBytesCallback, AsynchronousWriteCallback;

        public:
            // Constructor stores context, strand and configuration; creates ciphers if enabled.
            ITransmission(const ContextPtr& context, const StrandPtr& strand,
                const AppConfigurationPtr& configuration) noexcept;
            // Virtual destructor ensures proper cleanup in derived classes.
            virtual ~ITransmission() noexcept;

        public:
            // Statistics and QoS controllers – may be set by derived classes or users.
            std::shared_ptr<ITransmissionStatistics> Statistics;
            std::shared_ptr<ITransmissionQoS> QoS;

        public:
            // Simple inline accessors (noexcept for performance).
            AppConfigurationPtr                                                                     GetConfiguration() noexcept { return configuration_; }
            ContextPtr&                                                                             GetContext() noexcept { return context_; }
            StrandPtr&                                                                              GetStrand() noexcept { return strand_; }

        public:
            // Override of base Dispose to perform graceful shutdown and resource cleanup.
            virtual void                                                                            Dispose() noexcept override;
            // Force execution onto the correct scheduler/strand (pure virtual).
            virtual bool                                                                            ShiftToScheduler() noexcept = 0;
            // Return remote endpoint (pure virtual).
            virtual boost::asio::ip::tcp::endpoint                                                  GetRemoteEndPoint() noexcept = 0;

        public:
            // Client handshake: returns session ID and sets mux flag.
            virtual Int128                                                                          HandshakeClient(YieldContext& y, bool& mux) noexcept;
            // Server handshake: accepts a session ID and mux flag.
            virtual bool                                                                            HandshakeServer(YieldContext& y, const Int128& session_id, bool mux) noexcept;

        public:
            // High‑level encryption/decryption (may apply base94 when needed).
            std::shared_ptr<Byte>                                                                   Encrypt(Byte* data, int datalen, int& outlen) noexcept;
            std::shared_ptr<Byte>                                                                   Decrypt(Byte* data, int datalen, int& outlen) noexcept;
            // Coroutine‑aware read that returns decrypted payload.
            virtual std::shared_ptr<Byte>                                                           Read(YieldContext& y, int& outlen) noexcept;
            // Coroutine‑aware write that encrypts and sends payload.
            virtual bool                                                                            Write(YieldContext& y, const void* packet, int packet_length) noexcept;
            // Callback‑based asynchronous write (non‑yielding version).
            virtual bool                                                                            Write(const void* packet, int packet_length, const AsynchronousWriteCallback& cb) noexcept;

        protected:
            // Low‑level raw byte read – must be implemented by derived classes.
            virtual std::shared_ptr<Byte>                                                           DoReadBytes(YieldContext& y, int length) noexcept = 0;

        private:
            // Internal cleanup (called from destructor and Dispose).
            void                                                                                    Finalize() noexcept;
            // Cancel and release handshake timeout timer.
            void                                                                                    InternalHandshakeTimeoutClear() noexcept;
            // Arm handshake timeout with random jitter.
            bool                                                                                    InternalHandshakeTimeoutSet() noexcept;
            // Core client handshake logic (after timeout armed).
            Int128                                                                                  InternalHandshakeClient(YieldContext& y, bool& mux) noexcept;
            // Core server handshake logic (after timeout armed).
            bool                                                                                    InternalHandshakeServer(YieldContext& y, const Int128& session_id, bool mux) noexcept;

        private:
            // Bitfields (unsigned int for well‑defined behavior) – compact state flags.
            unsigned int                                                                            disposed_ : 1;      // true if transmission is disposed.
            unsigned int                                                                            frame_rn_ : 1;      // true if receive‑side simple header mode active.
            unsigned int                                                                            frame_tn_ : 1;      // true if transmit‑side simple header mode active.
            unsigned int                                                                            handshaked_ : 5;    // true if handshake completed.

            ContextPtr                                                                              context_;           // Asio io_context (never null after construction).
            StrandPtr                                                                               strand_;            // Strand for thread‑safe state access.
            DeadlineTimerPtr                                                                        timeout_;           // Handshake timeout timer (reset after success).
            CiphertextPtr                                                                           protocol_;          // Protocol‑layer cipher (optional).
            CiphertextPtr                                                                           transport_;         // Transport‑layer cipher (optional).
            AppConfigurationPtr                                                                     configuration_;     // Configuration (never null after construction).
        };

    } // namespace transmissions
} // namespace ppp