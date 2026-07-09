import Foundation
import NetworkExtension
import OpenPPP2

final class PacketFlowOutputQueue {
    static let batchLimit = 128
    static let highWater = 512
    static let maxDepth = 1024

    private let flow: NEPacketTunnelFlow
    private let consoleLoggingEnabled: Bool
    private let outputQueue = DispatchQueue(label: "io.github.openppp2.packet-tunnel.output", qos: .userInitiated)
    private let lock = NSLock()
    private var pendingPackets: [(Data, NSNumber)] = []
    private var flushScheduled = false
    private var droppedCount = 0

    var onBatchWritten: ((_ batch: [(Data, NSNumber)], _ ok: Bool) -> Void)?

    init(flow: NEPacketTunnelFlow, consoleLoggingEnabled: Bool = false) {
        self.flow = flow
        self.consoleLoggingEnabled = consoleLoggingEnabled
    }

    func enqueue(
        packet: UnsafeRawPointer,
        size: Int32,
        packetContext: UnsafeMutableRawPointer?,
        release: openppp2_ios_packet_release?
    ) -> Int32 {
        lock.lock()
        if pendingPackets.count >= Self.maxDepth {
            droppedCount += 1
            lock.unlock()
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
        pendingPackets.append((data, protocolNumber))
        let depth = pendingPackets.count
        let shouldFlushNow = depth >= Self.batchLimit
        let scheduleFlush = !flushScheduled && !shouldFlushNow
        if scheduleFlush {
            flushScheduled = true
        }
        lock.unlock()

        if shouldFlushNow {
            outputQueue.async { [weak self] in
                self?.flush(force: false)
            }
        } else if scheduleFlush {
            outputQueue.asyncAfter(deadline: .now() + 0.001) { [weak self] in
                self?.flush(force: false)
            }
        }
        return 1
    }

    func flush(force: Bool) {
        lock.lock()
        flushScheduled = false
        guard !pendingPackets.isEmpty else {
            lock.unlock()
            return
        }

        let takeCount = force
            ? pendingPackets.count
            : min(Self.batchLimit, pendingPackets.count)
        let batch = Array(pendingPackets.prefix(takeCount))
        pendingPackets.removeFirst(takeCount)
        let morePending = !pendingPackets.isEmpty
        if morePending && !flushScheduled {
            flushScheduled = true
        }
        lock.unlock()

        var packets: [Data] = []
        var protocols: [NSNumber] = []
        packets.reserveCapacity(batch.count)
        protocols.reserveCapacity(batch.count)
        for (data, protocolNumber) in batch {
            packets.append(data)
            protocols.append(protocolNumber)
        }

        let ok = flow.writePackets(packets, withProtocols: protocols)
        if !ok && consoleLoggingEnabled {
            NSLog(
                "OpenPPP2 PacketTunnel writePackets batch failed count=%d bytes=%d",
                batch.count,
                batch.reduce(0) { $0 + $1.0.count }
            )
        }

        onBatchWritten?(batch, ok)

        if morePending {
            outputQueue.async { [weak self] in
                self?.flush(force: false)
            }
        }
    }

    func shouldPauseReads() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return pendingPackets.count >= Self.highWater
    }

    func droppedCountSnapshot() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return droppedCount
    }

    func pendingDepthSnapshot() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return pendingPackets.count
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
