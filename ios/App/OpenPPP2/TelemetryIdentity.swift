import CryptoKit
import Foundation
import UIKit

enum TelemetryIdentity {
    private static let installNonceKey = "openppp2_machine_install_nonce_v1"

    static var machineId: String {
        let seed = [
            installNonce(),
            UIDevice.current.identifierForVendor?.uuidString ?? "",
            UIDevice.current.model,
            UIDevice.current.userInterfaceIdiom.telemetryLabel,
            deviceModel,
            TunnelSharedState.appGroupIdentifier,
            Bundle.main.object(forInfoDictionaryKey: "TeamIdentifierPrefix") as? String ?? ""
        ].joined(separator: "|")

        let digest = SHA256.hash(data: Data(seed.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    static var resourceAttributes: [String: OTLPAttributeValue] {
        var attrs: [String: OTLPAttributeValue] = [
            "machine.id": .string(machineId),
            "device.model": .string(deviceModel),
            "device.family": .string(UIDevice.current.userInterfaceIdiom.telemetryLabel),
            "os.name": .string(UIDevice.current.systemName),
            "os.version": .string(UIDevice.current.systemVersion)
        ]
        if let vendorId = UIDevice.current.identifierForVendor?.uuidString {
            attrs["device.vendor_id_hash"] = .string(hash("vendor|\(vendorId)"))
        }
        return attrs
    }

    static var nativeResourceAttributes: [String: String] {
        resourceAttributes.mapValues { value in
            switch value {
            case let .string(raw):
                return raw
            case let .int(raw):
                return String(raw)
            case let .bool(raw):
                return raw ? "true" : "false"
            }
        }
    }

    static func installIfNeeded() {
        _ = machineId
    }

    private static func installNonce() -> String {
        let defaults = sharedDefaults()
        if let existing = defaults.string(forKey: installNonceKey), !existing.isEmpty {
            return existing
        }

        let nonce = UUID().uuidString.lowercased()
        defaults.set(nonce, forKey: installNonceKey)
        return nonce
    }

    private static func sharedDefaults() -> UserDefaults {
        UserDefaults(suiteName: TunnelSharedState.appGroupIdentifier) ?? .standard
    }

    private static func hash(_ value: String) -> String {
        let digest = SHA256.hash(data: Data(value.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private static var deviceModel: String {
        var systemInfo = utsname()
        uname(&systemInfo)
        let capacity = MemoryLayout.size(ofValue: systemInfo.machine)
        return withUnsafePointer(to: &systemInfo.machine) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: capacity) {
                String(validatingUTF8: $0) ?? UIDevice.current.model
            }
        }
    }
}

private extension UIUserInterfaceIdiom {
    var telemetryLabel: String {
        switch self {
        case .phone:
            return "iphone"
        case .pad:
            return "ipad"
        case .tv:
            return "tv"
        case .carPlay:
            return "carplay"
        case .mac:
            return "mac"
        case .vision:
            return "vision"
        case .unspecified:
            fallthrough
        @unknown default:
            return "unspecified"
        }
    }
}
