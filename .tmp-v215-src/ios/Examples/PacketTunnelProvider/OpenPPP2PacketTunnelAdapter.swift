import Darwin
import Foundation
import NetworkExtension
import OpenPPP2

final class OpenPPP2PacketTunnelAdapter {
    private let flow: NEPacketTunnelFlow
    private var tap: OpaquePointer?
    private var isRunning = false

    init(flow: NEPacketTunnelFlow) {
        self.flow = flow
    }

    func start() -> Bool {
        guard tap == nil else {
            return true
        }

        let userData = Unmanaged.passUnretained(self).toOpaque()
        guard let createdTap = openppp2_ios_tap_create(openPPP2PacketWriter, userData) else {
            return false
        }

        tap = createdTap
        isRunning = true
        readPackets()
        return true
    }

    func stop() {
        isRunning = false

        if let tap {
            openppp2_ios_tap_destroy(tap)
            self.tap = nil
        }
    }

    private func readPackets() {
        guard isRunning else {
            return
        }

        flow.readPackets { [weak self] packets, _ in
            guard let self else {
                return
            }

            if self.isRunning, let tap = self.tap {
                for packet in packets {
                    packet.withUnsafeBytes { buffer in
                        guard let baseAddress = buffer.baseAddress, !buffer.isEmpty else {
                            return
                        }

                        _ = openppp2_ios_tap_input(tap, baseAddress, Int32(buffer.count))
                    }
                }
            }

            self.readPackets()
        }
    }

    fileprivate func writePacket(
        _ packet: UnsafeRawPointer?,
        size: Int32,
        packetContext: UnsafeMutableRawPointer?,
        release: openppp2_ios_packet_release?
    ) -> Int32 {
        guard let packet, size > 0 else {
            return 0
        }

        let data: Data
        if let release {
            data = Data(
                bytesNoCopy: UnsafeMutableRawPointer(mutating: packet),
                count: Int(size),
                deallocator: .custom { _, _ in
                    release(packetContext)
                }
            )
        } else {
            data = Data(bytes: packet, count: Int(size))
        }
        let protocolNumber = Self.protocolNumber(forFirstByte: packet.load(as: UInt8.self))
        return flow.writePackets([data], withProtocols: [protocolNumber]) ? 1 : 0
    }

    private static func protocolNumber(for packet: Data) -> NSNumber {
        guard let firstByte = packet.first else {
            return NSNumber(value: AF_INET)
        }

        return protocolNumber(forFirstByte: firstByte)
    }

    private static func protocolNumber(forFirstByte firstByte: UInt8) -> NSNumber {
        switch firstByte >> 4 {
        case 6:
            return NSNumber(value: AF_INET6)
        default:
            return NSNumber(value: AF_INET)
        }
    }
}

private func openPPP2PacketWriter(
    packet: UnsafeRawPointer?,
    packetSize: Int32,
    packetContext: UnsafeMutableRawPointer?,
    packetRelease: openppp2_ios_packet_release?,
    userData: UnsafeMutableRawPointer?
) -> Int32 {
    guard let userData else {
        return 0
    }

    let adapter = Unmanaged<OpenPPP2PacketTunnelAdapter>
        .fromOpaque(userData)
        .takeUnretainedValue()

    return adapter.writePacket(
        packet,
        size: packetSize,
        packetContext: packetContext,
        release: packetRelease
    )
}
