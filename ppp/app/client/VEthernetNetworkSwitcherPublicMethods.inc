#if defined(_WIN32)
                PaperAirplaneControllerPtr GetPaperAirplaneController() noexcept;
                virtual bool SetHttpProxyToSystemEnv() noexcept;
                virtual bool ClearHttpProxyToSystemEnv() noexcept;
#elif defined(_LINUX)
                ProtectorNetworkPtr GetProtectorNetwork() noexcept;
#endif

                std::shared_ptr<ppp::configurations::AppConfiguration> GetConfiguration() noexcept;
                std::shared_ptr<VEthernetExchanger> GetExchanger() noexcept;
                ppp::app::runtime::RuntimeReadiness GetRuntimeReadiness() noexcept;
                void RequestedIPv6(const ppp::string& value) noexcept;
                ppp::string RequestedIPv6() noexcept;
#if !defined(_ANDROID) && !defined(_IPHONE)
                boost::asio::ip::address LastAssignedIPv6() noexcept;
#else
                boost::asio::ip::address LastAssignedIPv6() noexcept { return {}; }
#endif
                std::shared_ptr<ppp::transmissions::ITransmissionQoS> GetQoS() noexcept;
                std::shared_ptr<ppp::transmissions::ITransmissionStatistics> GetStatistics() noexcept;
                std::shared_ptr<VirtualEthernetInformation> GetInformation() noexcept;
                VirtualEthernetInformationExtensions GetInformationExtensions() noexcept;
                VEthernetHttpProxySwitcherPtr GetHttpProxy() noexcept;
                VEthernetSocksProxySwitcherPtr GetSocksProxy() noexcept;
                RouteInformationTablePtr GetRib() noexcept;
                ForwardInformationTablePtr GetFib() noexcept;
                IForwardingPtr GetForwarding() noexcept;
                std::shared_ptr<aggligator::aggligator> GetAggligator() noexcept;
                RouteIPListTablePtr GetVbgp() noexcept;
                bool IsBlockQUIC() noexcept;
                bool IsMuxEnabled() noexcept;
                bool IsBypassIpAddress(const boost::asio::ip::address& ip) noexcept;

                virtual bool LoadAllDnsRules(const ppp::string& rules, bool load_file_or_string) noexcept;
                bool StaticMode(bool* static_mode) noexcept;
                bool ProxyOnly(bool* proxy_only) noexcept;
                uint16_t Mux(uint16_t* mux) noexcept;
                uint8_t MuxAcceleration(uint8_t* mux_acceleration) noexcept;

#if defined(_ANDROID) || defined(_IPHONE)
                void SetBypassIpList(ppp::string&& bypass_ip_list) noexcept;
#else
#if defined(_LINUX)
                bool ProtectMode(bool* protect_mode) noexcept;
#endif
                std::shared_ptr<ClientNetworkInterface> GetTapNetworkInterface() noexcept;
                std::shared_ptr<ClientNetworkInterface> GetUnderlyingNetworkInterface() noexcept;
                virtual void PreferredNgw(const boost::asio::ip::address& gw) noexcept;
                virtual void PreferredNic(const ppp::string& nic) noexcept;
                virtual bool AddLoadIPList(
                    const ppp::string& path,
#if defined(_LINUX)
                    const ppp::string& nic,
#endif
                    const boost::asio::ip::address& gw,
                    const ppp::string& url) noexcept;
                virtual ppp::string GetRemoteUri() noexcept;
#endif

                virtual bool Open(const std::shared_ptr<ITap>& tap) noexcept override;
                virtual void Dispose() noexcept override;
                virtual std::shared_ptr<ppp::threading::BufferswapAllocator> GetBufferAllocator() noexcept override;
                virtual bool BlockQUIC(bool value) noexcept;
#if !defined(_ANDROID) && !defined(_IPHONE)
                bool AddRoute() noexcept;
                bool DeleteRoute() noexcept;
#else
                bool AddAllRoute(const std::shared_ptr<ITap>& tap) noexcept;
#endif
