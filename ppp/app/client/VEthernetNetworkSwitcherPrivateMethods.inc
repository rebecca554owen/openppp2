#if !defined(_ANDROID) && !defined(_IPHONE)
                bool                                                                FixUnderlyingNgw() noexcept;
                void                                                                DeleteRoute() noexcept;
#else
                bool                                                                AddAllRoute(const std::shared_ptr<ITap>& tap) noexcept;
#endif

                bool                                                                RedirectDnsServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<UdpFrame>& frame, const std::shared_ptr<ppp::net::packet::BufferSegment>& messages) noexcept;
                const dns::DnsHostPorts&                                            DnsHostPortsFor(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept;
                void                                                                InvalidateDnsHostPorts() noexcept;
                bool                                                                EmplaceTimeout(void* k, const std::shared_ptr<ppp::threading::Timer::TimeoutEventHandler>& timeout) noexcept;
                bool                                                                DeleteTimeout(void* k) noexcept;

#if !defined(_ANDROID) && !defined(_IPHONE)
                bool                                                                TryApplyHostedNetworkRoutes() noexcept;
#else
                bool                                                                TryApplyHostedNetworkRoutes() noexcept { return true; }
#endif

                void                                                                ReleaseAllObjects() noexcept;
                void                                                                ReleaseAllPackets() noexcept;
                void                                                                ReleaseAllTimeouts() noexcept;

#if !defined(_ANDROID) && !defined(_IPHONE)
#if defined(_WIN32)
                bool                                                                UsePaperAirplaneController() noexcept;
#endif
                bool                                                                LoadAllIPListWithFilePaths(const boost::asio::ip::address& gw) noexcept;
#endif

                void                                                                Finalize() noexcept;
                bool                                                                AddRemoteEndPointToIPList(const boost::asio::ip::address& gw) noexcept;
                bool                                                                StaticEchoAddRemoteEndPoint(boost::asio::ip::udp::endpoint& remoteEP) noexcept;

#if !defined(_ANDROID) && !defined(_IPHONE)
                bool                                                                ApplyAssignedIPv6(const VirtualEthernetInformationExtensions& extensions) noexcept;
                void                                                                RestoreAssignedIPv6() noexcept;
                bool                                                                ApplyAssignedIPv4(const VirtualEthernetInformationExtensions& extensions) noexcept;
                void                                                                RestoreAssignedIPv4() noexcept;
#endif

                bool                                                                ERORTE(int ack_id) noexcept;
                bool                                                                PreparedAggregator() noexcept;
                bool                                                                IPAddressIsGatewayServer(UInt32 ip, UInt32 gw, UInt32 mask) noexcept;
