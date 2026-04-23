/**
 * @file ITransmission.h
 * @brief Declares the base encrypted transmission abstraction.
 */
#pragma once

/** @brief Project precompiled header and core dependencies. */
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

        /**
         * @brief Base class for encrypted, handshaked, coroutine-aware transport I/O.
         */
        class ITransmission : public ppp::net::asio::IAsynchronousWriteIoQueue {
            /** @brief Bridge helper that implements internal static read/write logic. */
            friend class ITransmissionBridge;
            /** @brief QoS helper requires direct access to transmission internals. */
            friend class ITransmissionQoS;

            /** @brief Deadline timer type used for handshake timeout control (monotonic, immune to wall-clock jumps). */
            typedef boost::asio::steady_timer                                                       DeadlineTimer;
            /** @brief Shared deadline timer pointer. */
            typedef std::shared_ptr<DeadlineTimer>                                                  DeadlineTimerPtr;

        public:
            /** @brief Application configuration type. */
            typedef ppp::configurations::AppConfiguration                                           AppConfiguration;
            /** @brief Shared application configuration pointer. */
            typedef std::shared_ptr<AppConfiguration>                                               AppConfigurationPtr;
            /** @brief Symmetric cipher wrapper type. */
            typedef ppp::cryptography::Ciphertext                                                   Ciphertext;
            /** @brief Shared cipher pointer. */
            typedef std::shared_ptr<Ciphertext>                                                     CiphertextPtr;
            /** @brief Coroutine yield context type. */
            typedef ppp::coroutines::YieldContext                                                   YieldContext;
            /** @brief Shared io_context pointer type. */
            typedef std::shared_ptr<boost::asio::io_context>                                        ContextPtr;
            /** @brief Shared strand pointer for serialized callback execution. */
            typedef std::shared_ptr<boost::asio::strand<boost::asio::io_context::executor_type>>    StrandPtr;
            /** @brief Asynchronous write completion callback type. */
            typedef ppp::function<void(bool)>                                                       AsynchronousWriteBytesCallback, AsynchronousWriteCallback;

        public:
            /**
             * @brief Initializes transmission context, strand, and cipher configuration.
             * @param context Shared io_context used by async operations.
             * @param strand Shared strand used for serialized state access.
             * @param configuration Application-level transmission configuration.
             */
            ITransmission(const ContextPtr& context, const StrandPtr& strand,
                const AppConfigurationPtr& configuration) noexcept;
            /** @brief Virtual destructor for polymorphic cleanup. */
            virtual ~ITransmission() noexcept;

        public:
            /** @brief Optional traffic statistics sink. */
            std::shared_ptr<ITransmissionStatistics> Statistics;
            /** @brief Optional QoS coordinator used by derived transports. */
            std::shared_ptr<ITransmissionQoS> QoS;

        public:
            /** @brief Gets current transmission configuration. */
            AppConfigurationPtr                                                                     GetConfiguration() noexcept { return configuration_; }
            /** @brief Gets mutable shared io_context reference. */
            ContextPtr&                                                                             GetContext() noexcept { return context_; }
            /** @brief Gets mutable shared strand reference. */
            StrandPtr&                                                                              GetStrand() noexcept { return strand_; }

        public:
            /** @brief Disposes transmission resources asynchronously. */
            virtual void                                                                            Dispose() noexcept override;
            /** @brief Moves transport execution to its scheduler if required. */
            virtual bool                                                                            ShiftToScheduler() noexcept = 0;
            /** @brief Returns remote TCP endpoint information. */
            virtual boost::asio::ip::tcp::endpoint                                                  GetRemoteEndPoint() noexcept = 0;

        public:
            /**
             * @brief Runs the client-side handshake sequence.
             * @param y Coroutine yield context.
             * @param mux Output flag indicating negotiated multiplexing capability.
             * @return Negotiated session identifier, or zero on failure.
             */
            virtual Int128                                                                          HandshakeClient(YieldContext& y, bool& mux) noexcept;
            /**
             * @brief Runs the server-side handshake sequence.
             * @param y Coroutine yield context.
             * @param session_id Session identifier provided by upper layer.
             * @param mux Requested multiplexing behavior.
             * @return true if handshake succeeds; otherwise false.
             */
            virtual bool                                                                            HandshakeServer(YieldContext& y, const Int128& session_id, bool mux) noexcept;

        public:
            /**
             * @brief Encrypts plaintext payload into transmission packet bytes.
             * @param data Input payload pointer.
             * @param datalen Input payload length.
             * @param outlen Output encrypted length.
             * @return Encrypted packet buffer, or null on failure.
             */
            std::shared_ptr<Byte>                                                                   Encrypt(Byte* data, int datalen, int& outlen) noexcept;
            /**
             * @brief Decrypts packet bytes into plaintext payload.
             * @param data Input packet pointer.
             * @param datalen Input packet length.
             * @param outlen Output plaintext length.
             * @return Decrypted payload buffer, or null on failure.
             */
            std::shared_ptr<Byte>                                                                   Decrypt(Byte* data, int datalen, int& outlen) noexcept;
            /**
             * @brief Reads and decrypts one payload from the underlying transport.
             * @param y Coroutine yield context.
             * @param outlen Output payload length.
             * @return Decrypted payload buffer, or null on failure.
             */
            virtual std::shared_ptr<Byte>                                                           Read(YieldContext& y, int& outlen) noexcept;
            /**
             * @brief Encrypts and writes payload bytes using coroutine flow.
             * @param y Coroutine yield context.
             * @param packet Payload pointer.
             * @param packet_length Payload length.
             * @return true if write succeeds; otherwise false.
             */
            virtual bool                                                                            Write(YieldContext& y, const void* packet, int packet_length) noexcept;
            /**
             * @brief Encrypts and writes payload bytes using callback flow.
             * @param packet Payload pointer.
             * @param packet_length Payload length.
             * @param cb Completion callback.
             * @return true if write is scheduled; otherwise false.
             */
            virtual bool                                                                            Write(const void* packet, int packet_length, const AsynchronousWriteCallback& cb) noexcept;

        protected:
            /**
             * @brief Reads raw bytes from derived transport implementation.
             * @param y Coroutine yield context.
             * @param length Number of bytes to read.
             * @return Raw byte buffer, or null on failure.
             */
            virtual std::shared_ptr<Byte>                                                           DoReadBytes(YieldContext& y, int length) noexcept = 0;

        private:
            /** @brief Performs internal resource cleanup. */
            void                                                                                    Finalize() noexcept;
            /** @brief Cancels and releases the handshake timeout timer. */
            void                                                                                    InternalHandshakeTimeoutClear() noexcept;
            /** @brief Arms handshake timeout with randomized jitter. */
            bool                                                                                    InternalHandshakeTimeoutSet() noexcept;
            /** @brief Executes core client handshake steps. */
            Int128                                                                                  InternalHandshakeClient(YieldContext& y, bool& mux) noexcept;
            /** @brief Executes core server handshake steps. */
            bool                                                                                    InternalHandshakeServer(YieldContext& y, const Int128& session_id, bool mux) noexcept;

        private:
            /**
             * @brief Strand-serialized bitfield state flags for transmission lifecycle and framing.
             *
             * @details These four bitfields occupy a single @c unsigned @c int storage unit as
             *          mandated by the C++ standard for adjacent bitfield members of the same
             *          underlying type.  Because they share one storage unit, the C++ memory model
             *          treats any access to the unit — even to a logically distinct bitfield within
             *          it — as an access to the entire object.
             *
             * @warning **Thread-safety invariant — MUST NOT be violated in derived classes.**
             *
             *          All reads and writes to @c disposed_, @c frame_rn_, @c frame_tn_, and
             *          @c handshaked_ MUST be performed exclusively from a handler that is already
             *          running on @c strand_.  Thread safety is guaranteed entirely by strand
             *          serialization, NOT by atomic operations.
             *
             *          Concurrent access from any code path that is not serialized through
             *          @c strand_ constitutes a data race and is undefined behavior under the
             *          C++ standard (ISO/IEC 14882, [intro.races]), regardless of which individual
             *          bitfield is targeted.  If a derived class needs to read or write any of
             *          these members from an off-strand context, that code path MUST be corrected
             *          to first dispatch through @c strand_ via @c asio::post or
             *          @c asio::dispatch before touching these fields.
             *
             * @note    Bitfield members cannot be made @c std::atomic.  The C++ standard does not
             *          permit @c std::atomic<T> to wrap a bitfield, and no compiler extension
             *          provides this.  Do NOT attempt to convert these members to @c std::atomic.
             *          The only member that is safe to access from off-strand code is
             *          @c finalized_ (an @c std::atomic<bool>), which serves as the one-shot gate
             *          for @c Finalize() and is intentionally separated from this storage unit.
             */
            /** @brief Set when transmission is disposed. */
            unsigned int                                                                            disposed_ : 1;      // true if transmission is disposed.
            /** @brief Set after receive path switches to simple header mode. */
            unsigned int                                                                            frame_rn_ : 1;      // true if receive‑side simple header mode active.
            /** @brief Set after transmit path switches to simple header mode. */
            unsigned int                                                                            frame_tn_ : 1;      // true if transmit‑side simple header mode active.
            /** @brief Handshake completion state flag storage. */
            unsigned int                                                                            handshaked_ : 5;    // true if handshake completed.

            /**
             * @brief One-shot guard ensuring Finalize() executes at most once.
             *
             * @details Cannot reuse the disposed_ bitfield for atomic CAS, so this separate
             *          std::atomic<bool> acts as the gate.  The first caller that flips it from
             *          false → true proceeds with teardown; all subsequent callers return early.
             */
            std::atomic<bool>                                                                       finalized_{false};

            /** @brief Backing io_context for async operation dispatch. */
            ContextPtr                                                                              context_;           // Asio io_context (never null after construction).
            /** @brief Strand for serialized asynchronous state transitions. */
            StrandPtr                                                                               strand_;            // Strand for thread‑safe state access.
            /** @brief Active handshake timeout timer, if armed. */
            DeadlineTimerPtr                                                                        timeout_;           // Handshake timeout timer (reset after success).
            /** @brief Optional protocol-layer cipher instance. */
            CiphertextPtr                                                                           protocol_;          // Protocol‑layer cipher (optional).
            /** @brief Optional transport-layer cipher instance. */
            CiphertextPtr                                                                           transport_;         // Transport‑layer cipher (optional).
            /** @brief Shared immutable transmission configuration. */
            AppConfigurationPtr                                                                     configuration_;     // Configuration (never null after construction).
        };

    } /** namespace transmissions */
} /** namespace ppp */
