#pragma once

/**
 * @file DnsResolver.h
 * @brief Multi-protocol upstream DNS resolver for provider-based dns-rules.
 */

#include <ppp/stdafx.h>

namespace ppp {
    namespace dns {

        enum class Protocol {
            UDP,
            TCP,
            DoH,
            DoT,
        };

        struct ServerEntry {
            Protocol                                        protocol = Protocol::UDP;
            ppp::string                                     url;
            ppp::string                                     hostname;
            ppp::string                                     address;
            ppp::vector<boost::asio::ip::address>           bootstrap_ips;
        };

        class DnsResolver final : public std::enable_shared_from_this<DnsResolver> {
        public:
            typedef ppp::function<bool(int native_handle)>  ProtectSocketCallback;
            typedef ppp::function<void(ppp::vector<Byte>)>  ResolveCallback;

        public:
            explicit DnsResolver(boost::asio::io_context& context) noexcept;

            void                                            SetProtectSocketCallback(const ProtectSocketCallback& cb) noexcept;

            /**
             * @brief Sets the client exit IP used as the ECS source address.
             *
             * @details When ECS is enabled and no override_ip is configured,
             *          this address is used for the EDNS Client Subnet option.
             *          Typically populated from the server's ClientExitIP field
             *          in VirtualEthernetInformationExtensions.
             *
             * @param ip  Client exit IPv4/IPv6 address.
             */
            void                                            SetExitIP(const boost::asio::ip::address& ip) noexcept;

            /**
             * @brief Configures EDNS Client Subnet (ECS) injection behaviour.
             *
             * @param enabled     When true, ECS OPT RR is injected into domestic queries.
             * @param override_ip Highest-priority ECS IP; empty string defers to exit_ip.
             */
            void                                            SetEcsConfig(bool enabled, const ppp::string& override_ip) noexcept;

            /**
             * @brief Enables or disables peer certificate verification for DoH/DoT.
             *
             * @details When enabled, DnsResolver verifies the upstream certificate
             *          chain using the project's bundled roots, optional cacert.pem,
             *          and system default CA locations. Hostname verification is
             *          also applied when SNI/hostname is available.
             */
            void                                            SetTlsVerifyPeer(bool verify_peer) noexcept { tls_verify_peer_ = verify_peer; }

            /**
             * @brief Stores default domestic and foreign provider names used as
             *        fallback when ResolveAsyncWithFallback is called.
             *
             * @param domestic  Provider short-name for domestic queries (e.g. "doh.pub").
             * @param foreign   Provider short-name for foreign  queries (e.g. "cloudflare").
             */
            void                                            SetDefaultProviders(
                const ppp::string&                          domestic,
                const ppp::string&                          foreign) noexcept;

            /**
             * @brief Resolves a DNS query through a named provider, with up to two
             *        additional fallback providers tried in order on failure.
             *
             * @details Provider selection order:
             *          1. @p provider_name
             *          2. @p fallback1   (may be empty)
             *          3. @p fallback2   (may be empty)
             *
             *          Each step delegates to ResolveAsync, which itself tries all
             *          protocols (DoH → DoT → TCP → UDP) for that provider.  The
             *          callback is invoked exactly once with the first successful
             *          response, or with an empty vector if every attempt fails.
             *
             * @param provider_name  Primary provider short-name.
             * @param fallback1      First fallback provider short-name (or empty).
             * @param fallback2      Second fallback provider short-name (or empty).
             * @param packet         Raw DNS query bytes.
             * @param length         Length of @p packet in bytes.
             * @param callback       Completion callback; invoked exactly once.
             */
            void                                            ResolveAsyncWithFallback(
                const ppp::string&                          provider_name,
                const ppp::string&                          fallback1,
                const ppp::string&                          fallback2,
                const Byte*                                 packet,
                int                                         length,
                const ResolveCallback&                      callback) noexcept;

            void                                            ResolveAsync(
                const ppp::string&                          provider_name,
                bool                                        domestic,
                const Byte*                                 packet,
                int                                         length,
                const ResolveCallback&                      callback) noexcept;

            static bool                                     HasProvider(const ppp::string& name) noexcept;
            static const ppp::vector<ServerEntry>*          GetProvider(const ppp::string& name) noexcept;

        private:
            void                                            TryProtocols(
                std::shared_ptr<ppp::vector<ServerEntry> >  entries,
                std::size_t                                 index,
                std::shared_ptr<ppp::vector<Byte> >         packet,
                const ResolveCallback&                      callback) noexcept;

            void                                            SendUdp(
                const ServerEntry&                          entry,
                std::shared_ptr<ppp::vector<Byte> >         packet,
                const ResolveCallback&                      callback) noexcept;

            void                                            SendTcp(
                const ServerEntry&                          entry,
                std::shared_ptr<ppp::vector<Byte> >         packet,
                const ResolveCallback&                      callback) noexcept;

            void                                            SendDoh(
                const ServerEntry&                          entry,
                std::shared_ptr<ppp::vector<Byte> >         packet,
                const ResolveCallback&                      callback) noexcept;

            void                                            SendDot(
                const ServerEntry&                          entry,
                std::shared_ptr<ppp::vector<Byte> >         packet,
                const ResolveCallback&                      callback) noexcept;

            bool                                            ProtectSocket(int native_handle) noexcept;

            /**
             * @brief Returns the effective ECS IP address (override_ip > exit_ip).
             *
             * @return ECS IP address, or unspecified if none available.
             */
            boost::asio::ip::address                        GetEcsIp() const noexcept;

            /**
             * @brief Appends an EDNS Client Subnet OPT RR to a raw DNS query packet.
             *
             * @details Modifies @p packet in-place.  If the packet already contains
             *          additional records (ARCOUNT > 0) or is too short, the packet
             *          is left unchanged and the function returns false.  This
             *          conservative guard avoids generating illegal double-OPT packets.
             *
             * @param packet  DNS query packet bytes (modified in-place on success).
             * @param ecs_ip  IPv4 address to embed in the ECS option; last byte is
             *                zeroed to represent a /24 prefix.
             * @return true if the OPT RR was appended; false on error or skip.
             */
            static bool                                     InjectEcsOptRr(ppp::vector<Byte>& packet, const boost::asio::ip::address& ecs_ip) noexcept;

        private:
            boost::asio::io_context&                        context_;
            ProtectSocketCallback                           protect_socket_;
            ppp::string                                     default_domestic_;
            ppp::string                                     default_foreign_;
            boost::asio::ip::address                        exit_ip_;
            bool                                            ecs_enabled_ = false;
            ppp::string                                     ecs_override_ip_;
            bool                                            tls_verify_peer_ = true;
        };

    } // namespace dns
} // namespace ppp
