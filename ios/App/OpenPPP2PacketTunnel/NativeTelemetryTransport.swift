import Foundation
import NetworkExtension
import OpenPPP2

enum NativeTelemetryTransport {
    private static var installed = false
    private static let uploadQueue = DispatchQueue(label: "io.github.openppp2.native-telemetry", qos: .utility)
    private static let stateLock = NSLock()
    private static var pendingPosts: [(URL, Data)] = []
    private static var workerScheduled = false
    private static var droppedPosts = 0
    private static let maxPendingPosts = 16
    private static let session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.httpMaximumConnectionsPerHost = 1
        config.timeoutIntervalForRequest = 3
        config.timeoutIntervalForResource = 4
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        return URLSession(configuration: config)
    }()

    static func install() {
        guard !installed else { return }
        installed = true
        openppp2_ios_set_telemetry_http_post(nativeHttpPost, nil)
        openppp2_ios_clear_telemetry_resource_attributes()
        for (key, value) in TelemetryIdentity.nativeResourceAttributes {
            openppp2_ios_set_telemetry_resource_attribute(key, value)
        }
    }

    private static let nativeHttpPost: @convention(c) (
        UnsafePointer<CChar>?,
        UnsafeRawPointer?,
        Int32,
        UnsafeMutableRawPointer?
    ) -> Int32 = { urlPtr, bodyPtr, bodyLen, _ in
        guard let urlPtr,
              let bodyPtr,
              bodyLen > 0,
              let url = URL(string: String(cString: urlPtr))
        else {
            return 0
        }

        let body = Data(bytes: bodyPtr, count: Int(bodyLen))
        return enqueuePost(url: url, body: body) ? 1 : 0
    }

    /// Accept into a bounded queue; never block the native dataplane thread.
    private static func enqueuePost(url: URL, body: Data) -> Bool {
        stateLock.lock()
        if pendingPosts.count >= maxPendingPosts {
            droppedPosts += 1
            if droppedPosts == 1 || droppedPosts % 32 == 0 {
                NSLog("OpenPPP2 native telemetry queue full; dropped=%d", droppedPosts)
            }
            stateLock.unlock()
            return false
        }

        pendingPosts.append((url, body))
        let shouldSchedule = !workerScheduled
        if shouldSchedule {
            workerScheduled = true
        }
        stateLock.unlock()

        if shouldSchedule {
            uploadQueue.async {
                drainPendingPosts()
            }
        }
        return true
    }

    private static func drainPendingPosts() {
        while true {
            stateLock.lock()
            if pendingPosts.isEmpty {
                workerScheduled = false
                stateLock.unlock()
                return
            }
            let item = pendingPosts.removeFirst()
            stateLock.unlock()

            _ = performPost(url: item.0, body: item.1)
        }
    }

    private static func performPost(url: URL, body: Data) -> Bool {
        let semaphore = DispatchSemaphore(value: 0)
        var accepted = false

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 3
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = body

        session.dataTask(with: request) { _, response, error in
            if error == nil,
               let http = response as? HTTPURLResponse,
               (200..<300).contains(http.statusCode) {
                accepted = true
            } else if let error {
                NSLog("OpenPPP2 native telemetry upload failed: %@", error.localizedDescription)
            } else if let http = response as? HTTPURLResponse {
                NSLog("OpenPPP2 native telemetry upload rejected: HTTP %d", http.statusCode)
            }
            semaphore.signal()
        }.resume()

        _ = semaphore.wait(timeout: .now() + 4)
        return accepted
    }

    /// Block briefly so queued native OTLP posts can finish before the extension exits.
    static func flushPendingUploads(timeout: TimeInterval = 3) {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            stateLock.lock()
            let pending = pendingPosts.count
            let active = workerScheduled
            stateLock.unlock()
            if pending == 0 && !active {
                return
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
    }

    /// Synchronous OTLP log export for tunnel stop; must complete before the extension process exits.
    static func exportStopEvent(
        settings: TelemetrySettings,
        reason: NEProviderStopReason,
        extraAttributes: [String: OTLPAttributeValue] = [:]
    ) {
        guard settings.canUpload else {
            NSLog("OpenPPP2 PacketTunnel stop telemetry skipped: upload disabled")
            return
        }

        var attributes: [String: OTLPAttributeValue] = [
            "openppp2.component": .string("packet_tunnel"),
            "openppp2.stop_reason.code": .int(Int64(reason.rawValue)),
            "openppp2.stop_reason.name": .string(reason.telemetryLabel),
        ]
        for (key, value) in extraAttributes {
            attributes[key] = value
        }

        let record = OTLPLogRecord(
            timeUnixNano: UInt64(Date().timeIntervalSince1970 * 1_000_000_000),
            severityText: "INFO",
            body: "packet_tunnel stop reason=\(reason.telemetryLabel) code=\(reason.rawValue)",
            attributes: attributes
        )

        let exporter = OTLPHTTPLogExporter(
            settings: settings,
            session: session,
            scopeName: "openppp2.ios.packet_tunnel",
            scopeVersion: nil
        )

        let semaphore = DispatchSemaphore(value: 0)
        var exportError: Error?
        exporter.export(records: [record]) { result in
            if case let .failure(error) = result {
                exportError = error
            }
            semaphore.signal()
        }
        _ = semaphore.wait(timeout: .now() + 2)

        if let exportError {
            NSLog("OpenPPP2 PacketTunnel stop telemetry upload failed: %@", exportError.localizedDescription)
        } else {
            NSLog("OpenPPP2 PacketTunnel stop telemetry uploaded reason=%@", reason.telemetryLabel)
        }
    }
}

extension NEProviderStopReason {
    var telemetryLabel: String {
        switch rawValue {
        case 0: return "none"
        case 1: return "user_initiated"
        case 2: return "provider_failed"
        case 3: return "no_network"
        case 4: return "network_change"
        case 5: return "provider_disabled"
        case 6: return "auth_canceled"
        case 7: return "config_failed"
        case 8: return "idle_timeout"
        case 9: return "config_disabled"
        case 10: return "config_removed"
        case 11: return "supervisor"
        default: return "unknown(\(rawValue))"
        }
    }
}
