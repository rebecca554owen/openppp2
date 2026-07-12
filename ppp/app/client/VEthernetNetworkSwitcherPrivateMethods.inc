#if !defined(_ANDROID) && !defined(_IPHONE)
                bool                                                                FixUnderlyingNgw() noexcept;
#endif

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

                /** Caller must already hold the platform-appropriate DNS cache mutex. */
                void                                                                InvalidateDnsHostPortsLocked() noexcept {
                    dns_host_ports_cache_.reset();
                    dns_host_ports_exchanger_.reset();
                }

#if !defined(_ANDROID) && !defined(_IPHONE)
                bool                                                                ApplyAssignedIPv6(const VirtualEthernetInformationExtensions& extensions) noexcept;
                void                                                                RestoreAssignedIPv6() noexcept;
                bool                                                                ApplyAssignedIPv4(const VirtualEthernetInformationExtensions& extensions) noexcept;
                void                                                                RestoreAssignedIPv4() noexcept;
#endif

                bool                                                                ERORTE(int ack_id) noexcept;
                bool                                                                PreparedAggregator() noexcept;
                bool                                                                IPAddressIsGatewayServer(UInt32 ip, UInt32 gw, UInt32 mask) noexcept;
