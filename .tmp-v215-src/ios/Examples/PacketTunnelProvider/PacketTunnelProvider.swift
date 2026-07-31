import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var adapter: OpenPPP2PacketTunnelAdapter?

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.0.0.1")

        let ipv4 = NEIPv4Settings(
            addresses: ["10.0.0.2"],
            subnetMasks: ["255.255.255.0"]
        )
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error {
                completionHandler(error)
                return
            }

            guard let self else {
                completionHandler(nil)
                return
            }

            let adapter = OpenPPP2PacketTunnelAdapter(flow: self.packetFlow)
            guard adapter.start() else {
                completionHandler(NSError(
                    domain: "OpenPPP2PacketTunnel",
                    code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Unable to create OpenPPP2 iOS tap"]
                ))
                return
            }

            self.adapter = adapter
            completionHandler(nil)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        adapter?.stop()
        adapter = nil
        completionHandler()
    }
}
