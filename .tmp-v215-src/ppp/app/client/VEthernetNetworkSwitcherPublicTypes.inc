                typedef ClientNetworkInterface                                        NetworkInterface;
                typedef ppp::app::protocol::VirtualEthernetInformation              VirtualEthernetInformation;
                typedef ppp::app::protocol::VirtualEthernetInformationExtensions    VirtualEthernetInformationExtensions;
                typedef proxys::VEthernetHttpProxySwitcher                          VEthernetHttpProxySwitcher;
                typedef std::shared_ptr<VEthernetHttpProxySwitcher>                 VEthernetHttpProxySwitcherPtr;
                typedef proxys::VEthernetSocksProxySwitcher                         VEthernetSocksProxySwitcher;
                typedef std::shared_ptr<VEthernetSocksProxySwitcher>                VEthernetSocksProxySwitcherPtr;
                typedef ppp::function<void(VEthernetNetworkSwitcher*, UInt64)>      VEthernetTickEventHandler;
                typedef ppp::transmissions::ITransmissionStatistics                   ITransmissionStatistics;
                typedef std::shared_ptr<ITransmissionStatistics>                    ITransmissionStatisticsPtr;
                typedef ppp::net::native::RouteInformationTable                     RouteInformationTable;
                typedef std::shared_ptr<RouteInformationTable>                      RouteInformationTablePtr;
                typedef ppp::net::native::ForwardInformationTable                   ForwardInformationTable;
                typedef std::shared_ptr<ForwardInformationTable>                    ForwardInformationTablePtr;
                typedef ppp::unordered_map<ppp::string, ppp::string>                RouteIPListTable;
                typedef std::shared_ptr<RouteIPListTable>                           RouteIPListTablePtr;

#if defined(_WIN32)
                typedef lsp::PaperAirplaneController                                PaperAirplaneController;
                typedef std::shared_ptr<PaperAirplaneController>                    PaperAirplaneControllerPtr;
#elif defined(_LINUX)
                typedef ppp::net::ProtectorNetwork                                    ProtectorNetwork;
                typedef std::shared_ptr<ProtectorNetwork>                           ProtectorNetworkPtr;
#endif
