import Foundation

public enum TunnelRuntimeBridge {
    public static func decodeSnapshot(_ data: Data) throws -> RuntimeSnapshot {
        try JSONDecoder().decode(RuntimeSnapshot.self, from: data)
    }

    public static func decodeSnapshot(_ text: String) throws -> RuntimeSnapshot {
        guard let data = text.data(using: .utf8) else {
            throw CocoaError(.fileReadInapplicableStringEncoding)
        }
        return try decodeSnapshot(data)
    }
}
