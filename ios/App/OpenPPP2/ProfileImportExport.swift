import Foundation

struct ProfileExportBundle: Codable, Equatable {
    static let exportType = "openppp2-profile-export"
    static let supportedVersion = 1

    var type: String
    var version: Int
    var exportedAtMs: Int
    var activeProfileId: String?
    var profiles: [ConfigProfile]

    init(
        exportedAtMs: Int = Int(Date().timeIntervalSince1970 * 1000),
        activeProfileId: String? = nil,
        profiles: [ConfigProfile]
    ) {
        type = Self.exportType
        version = Self.supportedVersion
        self.exportedAtMs = exportedAtMs
        self.activeProfileId = activeProfileId
        self.profiles = profiles
    }
}

enum ProfileImportMode {
    case merge
    case replace
}

struct ProfileImportResult: Equatable {
    var importedCount: Int
    var updatedCount: Int
    var addedCount: Int
}

enum ProfileImportExportError: LocalizedError, Equatable {
    case payloadTooLarge
    case invalidFormat
    case unsupportedType(String)
    case unsupportedVersion(Int)
    case emptyProfiles
    case profileNotFound

    var errorDescription: String? {
        switch self {
        case .payloadTooLarge:
            return "配置文件过大（上限 2MB）。"
        case .invalidFormat:
            return "无法解析配置文件。"
        case let .unsupportedType(value):
            return "不支持的配置类型：\(value)"
        case let .unsupportedVersion(value):
            return "不支持的配置版本：\(value)"
        case .emptyProfiles:
            return "配置文件中没有可导入的 profile。"
        case .profileNotFound:
            return "找不到要导出的配置。"
        }
    }
}

enum ProfileImportExportCodec {
    static let maxPayloadBytes = 2 * 1024 * 1024

    static func encode(_ bundle: ProfileExportBundle) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(bundle)
    }

    static func decode(_ data: Data) throws -> ProfileExportBundle {
        guard data.count <= maxPayloadBytes else {
            throw ProfileImportExportError.payloadTooLarge
        }

        let decoder = JSONDecoder()
        guard let bundle = try? decoder.decode(ProfileExportBundle.self, from: data) else {
            throw ProfileImportExportError.invalidFormat
        }
        try validate(bundle)
        return bundle
    }

    static func validate(_ bundle: ProfileExportBundle) throws {
        guard bundle.type == ProfileExportBundle.exportType else {
            throw ProfileImportExportError.unsupportedType(bundle.type)
        }
        guard bundle.version == ProfileExportBundle.supportedVersion else {
            throw ProfileImportExportError.unsupportedVersion(bundle.version)
        }
        guard !bundle.profiles.isEmpty else {
            throw ProfileImportExportError.emptyProfiles
        }
    }

    static func allProfilesFilename(date: Date = Date()) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyy-MM-dd"
        return "openppp2-profiles-\(formatter.string(from: date)).json"
    }

    static func singleProfileFilename(name: String) -> String {
        let sanitized = name
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "/", with: "-")
            .replacingOccurrences(of: ":", with: "-")
        let base = sanitized.isEmpty ? "profile" : sanitized
        return "openppp2-profile-\(base).json"
    }
}

enum ProfileImportExportLogic {
    static func applyImport(
        bundle: ProfileExportBundle,
        mode: ProfileImportMode,
        existingProfiles: [ConfigProfile],
        activeProfileId: String?
    ) -> (profiles: [ConfigProfile], activeProfileId: String?, result: ProfileImportResult) {
        switch mode {
        case .merge:
            return merge(bundle: bundle, into: existingProfiles, activeProfileId: activeProfileId)
        case .replace:
            return replace(bundle: bundle)
        }
    }

    private static func merge(
        bundle: ProfileExportBundle,
        into existingProfiles: [ConfigProfile],
        activeProfileId: String?
    ) -> (profiles: [ConfigProfile], activeProfileId: String?, result: ProfileImportResult) {
        var list = existingProfiles
        var updatedCount = 0
        var addedCount = 0

        for profile in bundle.profiles {
            if let index = list.firstIndex(where: { $0.id == profile.id }) {
                list[index] = profile
                updatedCount += 1
            } else {
                list.append(profile)
                addedCount += 1
            }
        }

        return (
            list,
            activeProfileId,
            ProfileImportResult(
                importedCount: bundle.profiles.count,
                updatedCount: updatedCount,
                addedCount: addedCount
            )
        )
    }

    private static func replace(
        bundle: ProfileExportBundle
    ) -> (profiles: [ConfigProfile], activeProfileId: String?, result: ProfileImportResult) {
        let list = bundle.profiles
        let activeId: String
        if let requested = bundle.activeProfileId,
           list.contains(where: { $0.id == requested }) {
            activeId = requested
        } else {
            activeId = list[0].id
        }

        return (
            list,
            activeId,
            ProfileImportResult(
                importedCount: bundle.profiles.count,
                updatedCount: 0,
                addedCount: bundle.profiles.count
            )
        )
    }
}
