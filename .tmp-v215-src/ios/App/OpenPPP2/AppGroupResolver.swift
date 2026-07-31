import Foundation

enum AppGroupResolver {
    static func resolve(configured: String?, bundleIdentifier: String?, defaultGroup: String = "group.openppp2") -> String {
        if let configured {
            let trimmed = configured.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty {
                return trimmed
            }
        }
        if let bundleIdentifier, !bundleIdentifier.isEmpty {
            return "group." + bundleIdentifier
        }
        return defaultGroup
    }
}
