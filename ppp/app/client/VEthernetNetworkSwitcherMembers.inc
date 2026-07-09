                std::shared_ptr<VEthernetExchanger>                                 exchanger_;
                std::shared_ptr<ppp::configurations::AppConfiguration>              configuration_;
                ppp::string                                                         requested_ipv6_;
                std::shared_ptr<ppp::transmissions::ITransmissionQoS>                 qos_;
                std::shared_ptr<ppp::transmissions::ITransmissionStatistics>          statistics_;
                VEthernetIcmpPacketTable                                            icmppackets_;
                std::unique_ptr<QuicRejectRateLimiter>                              quic_reject_limiter_;
                struct {
                    int                                                             icmppackets_aid_  = 0;
                    bool                                                            block_quic_       = false;
                    bool                                                            static_mode_      = false;
                    bool                                                            proxy_only_       = false;
                    uint16_t                                                        mux_              = 0;
                    uint8_t                                                         mux_acceleration_ = 0;
                };
                VEthernetHttpProxySwitcherPtr                                       http_proxy_;
                VEthernetSocksProxySwitcherPtr                                      socks_proxy_;
                std::unique_ptr<SwitcherTimeoutRegistry>                            timeout_registry_;
                std::unique_ptr<dns::DnsInterceptor>                                dns_interceptor_;
                RouteInformationTablePtr                                            rib_;
                ForwardInformationTablePtr                                          fib_;
                RouteInformationTablePtr                                            peer_prefix_rib_;
                ForwardInformationTablePtr                                          peer_prefix_fib_;
                RouteIPListTablePtr                                                 vbgp_;
                ppp::string                                                         server_ru_;
                std::shared_ptr<aggligator::aggligator>                             aggligator_;
                IForwardingPtr                                                      forwarding_;
                std::unique_ptr<VirtualEthernetInformationExtensions>               information_extensions_;
                ppp::vector<ppp::app::protocol::PeerPrefixRouteEntry>               dynamic_peer_routes_;
                ppp::vector<net::native::RouteEntry>                                applied_peer_prefix_routes_;

#if !defined(_ANDROID) && !defined(_IPHONE)
                SynchronizedObject                                                  prdr_;
#if defined(_LINUX)
                bool                                                                protect_mode_  = false;
                ppp::unordered_map<uint32_t, ppp::string>                           nics_;
#endif
#endif

#if defined(_LINUX)
                ProtectorNetworkPtr                                                 protect_network_;
#endif

#if defined(_ANDROID) || defined(_IPHONE)
                ppp::string                                                         bypass_ip_list_;
#else
                bool                                                                route_added_   = false;
                bool                                                                route_apply_ready_ = false;
                LoadIPListFileVectorPtr                                             ribs_;
                std::shared_ptr<ClientNetworkInterface>                             tun_ni_;
                std::shared_ptr<ClientNetworkInterface>                             underlying_ni_;
                ppp::string                                                         preferred_nic_;
                boost::asio::ip::address                                            preferred_ngw_;
                ppp::unordered_set<uint32_t>                                        dns_serverss_[3];

#if defined(_WIN32)
                PaperAirplaneControllerPtr                                          paper_airplane_ctrl_;
                ppp::vector<MIB_IPFORWARDROW>                                       default_routes_;
                AllNicDnsServerAddresses                                            ni_dns_servers_;
#elif defined(_LINUX)
                ppp::string                                                         ni_dns_servers_;
                RouteInformationTablePtr                                            default_routes_;
#endif
#endif
                std::unique_ptr<RouteTableManager>                                  route_table_;
                std::unique_ptr<AssignedAddressManager>                             address_manager_;
                std::unique_ptr<ClientConnectionTeardown>                           teardown_;
                std::unique_ptr<ClientConnectionOpener>                           connection_opener_;
                std::unique_ptr<ClientPacketDispatchHandler>                        packet_dispatch_;
                std::unique_ptr<ClientBypassRouteLoader>                          bypass_loader_;
                std::unique_ptr<PeerPrefixRouteManager>                         peer_prefix_routes_;
                std::unique_ptr<AggregatorLoader>                               aggregator_loader_;
                std::unique_ptr<RemoteEndpointLoader>                           remote_endpoint_loader_;
                std::unique_ptr<dns::DnsHostPorts>                                  dns_host_ports_cache_;
                std::weak_ptr<VEthernetExchanger>                                 dns_host_ports_exchanger_;
