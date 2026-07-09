import Foundation

struct TelemetrySettings: Codable, Equatable {
    enum Destination: String, Codable, CaseIterable {
        case developer
        case custom

        var displayName: String {
            switch self {
            case .developer:
                return "开发者默认"
            case .custom:
                return "自定义"
            }
        }
    }

    var uploadEnabled: Bool = false
    var destination: Destination = .developer
    var customEndpoint: String = ""
    var includeCrashReports: Bool = true
    var includeNativeTelemetry: Bool = true
    var nativeLogLevel: Int = 1
    var nativeMetricsEnabled: Bool = false
    var nativeSpansEnabled: Bool = false

    var effectiveEndpoint: String {
        switch destination {
        case .developer:
            return Self.developerEndpoint
        case .custom:
            return customEndpoint.trimmingCharacters(in: .whitespacesAndNewlines)
        }
    }

    var canUpload: Bool {
        uploadEnabled && !effectiveEndpoint.isEmpty
    }

    static let developerEndpoint =
        Bundle.main.object(forInfoDictionaryKey: "OpenPPP2TelemetryDeveloperEndpoint") as? String ?? ""

    static let disabled = TelemetrySettings(
        uploadEnabled: false,
        destination: .developer,
        customEndpoint: "",
        includeCrashReports: false,
        includeNativeTelemetry: false,
        nativeLogLevel: 1,
        nativeMetricsEnabled: false,
        nativeSpansEnabled: false
    )
}

struct DebugSettings: Codable, Equatable {
    var packetFlowDiagnosticsEnabled: Bool = false
    var packetFlowConsoleLoggingEnabled: Bool = false
    var packetFlowTelemetryEnabled: Bool = false
}

struct ProviderCommand: Codable {
    let command: String
    var telemetry: TelemetrySettings?
}

final class TelemetrySettingsStore {
    static let shared = TelemetrySettingsStore()
    static let didChangeNotification = Notification.Name("OpenPPP2TelemetrySettingsDidChange")

    private let defaults = UserDefaults.standard
    private let key = "openppp2_telemetry_settings_v1"
    private let autoConfiguredEndpointKey = "openppp2_telemetry_auto_configured_endpoint_v1"
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    private init() {}

    func settings() -> TelemetrySettings {
        rememberDeveloperEndpointIfNeeded()
        return savedSettings() ?? TelemetrySettings()
    }

    func save(_ settings: TelemetrySettings) {
        persist(settings, notify: true)
    }

    private func savedSettings() -> TelemetrySettings? {
        guard let data = defaults.data(forKey: key),
              let settings = try? decoder.decode(TelemetrySettings.self, from: data)
        else {
            return nil
        }
        return settings
    }

    private func rememberDeveloperEndpointIfNeeded() {
        let endpoint = TelemetrySettings.developerEndpoint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !endpoint.isEmpty else { return }
        guard defaults.string(forKey: autoConfiguredEndpointKey) != endpoint else { return }

        defaults.set(endpoint, forKey: autoConfiguredEndpointKey)
        if var settings = savedSettings(), settings.destination != .developer {
            settings.destination = .developer
            persist(settings, notify: true)
        }
    }

    private func persist(_ settings: TelemetrySettings, notify: Bool) {
        if let data = try? encoder.encode(settings) {
            defaults.set(data, forKey: key)
        }
        if notify {
            NotificationCenter.default.post(name: Self.didChangeNotification, object: self)
        }
    }
}

struct TelemetryUploadSummary: Codable, Equatable {
    var attempted: Int = 0
    var uploaded: Int = 0
    var failed: Int = 0
    var skipped: Int = 0
    var lastError: String?

    var isEmpty: Bool {
        attempted == 0 && uploaded == 0 && failed == 0 && skipped == 0
    }

    mutating func merge(_ other: TelemetryUploadSummary) {
        attempted += other.attempted
        uploaded += other.uploaded
        failed += other.failed
        skipped += other.skipped
        lastError = other.lastError ?? lastError
    }

    var displayText: String {
        if skipped > 0 && attempted == 0 {
            return "已跳过：未开启上传或 endpoint 为空"
        }
        if failed == 0 {
            return uploaded == 0 ? "没有待上传报告" : "已上传 \(uploaded) 个报告"
        }
        return "已上传 \(uploaded) 个，失败 \(failed) 个"
    }
}

struct OTLPLogRecord {
    var timeUnixNano: UInt64
    var severityText: String
    var body: String
    var attributes: [String: OTLPAttributeValue]
}

enum OTLPAttributeValue {
    case string(String)
    case int(Int64)
    case bool(Bool)

    var jsonValue: [String: Any] {
        switch self {
        case let .string(value):
            return ["stringValue": value]
        case let .int(value):
            return ["intValue": String(value)]
        case let .bool(value):
            return ["boolValue": value]
        }
    }
}

enum OTLPExporterError: LocalizedError {
    case disabled
    case invalidEndpoint
    case invalidPayload
    case badStatus(Int, String)
    case missingResponse

    var errorDescription: String? {
        switch self {
        case .disabled:
            return "遥测上传未开启"
        case .invalidEndpoint:
            return "OpenTelemetry endpoint 无效"
        case .invalidPayload:
            return "OpenTelemetry payload 生成失败"
        case let .badStatus(code, body):
            return body.isEmpty ? "OpenTelemetry 上传失败：HTTP \(code)" : "OpenTelemetry 上传失败：HTTP \(code) \(body)"
        case .missingResponse:
            return "OpenTelemetry 上传没有收到 HTTP 响应"
        }
    }
}

final class OTLPHTTPLogExporter {
    private let settings: TelemetrySettings
    private let session: URLSession
    private let scopeName: String
    private let scopeVersion: String?

    init(
        settings: TelemetrySettings,
        session: URLSession = .shared,
        scopeName: String = "openppp2.ios.crash",
        scopeVersion: String? = nil
    ) {
        self.settings = settings
        self.session = session
        self.scopeName = scopeName
        self.scopeVersion = scopeVersion
    }

    func export(records: [OTLPLogRecord], completion: @escaping (Result<Void, Error>) -> Void) {
        guard settings.canUpload else {
            completion(.failure(OTLPExporterError.disabled))
            return
        }

        guard !records.isEmpty else {
            completion(.success(()))
            return
        }

        guard let url = Self.logsURL(from: settings.effectiveEndpoint) else {
            completion(.failure(OTLPExporterError.invalidEndpoint))
            return
        }

        guard JSONSerialization.isValidJSONObject(payload(records: records)),
              let body = try? JSONSerialization.data(withJSONObject: payload(records: records), options: [])
        else {
            completion(.failure(OTLPExporterError.invalidPayload))
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 12
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = body

        session.dataTask(with: request) { data, response, error in
            if let error {
                completion(.failure(error))
                return
            }

            guard let http = response as? HTTPURLResponse else {
                completion(.failure(OTLPExporterError.missingResponse))
                return
            }

            guard (200..<300).contains(http.statusCode) else {
                let text = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
                completion(.failure(OTLPExporterError.badStatus(http.statusCode, text)))
                return
            }

            completion(.success(()))
        }.resume()
    }

    private func payload(records: [OTLPLogRecord]) -> [String: Any] {
        [
            "resourceLogs": [
                [
                    "resource": [
                        "attributes": resourceAttributes()
                    ],
                    "scopeLogs": [
                        [
                            "scope": [
                                "name": scopeName,
                                "version": scopeVersion ?? appVersion
                            ],
                            "logRecords": records.map(Self.logRecordJson(_:))
                        ]
                    ]
                ]
            ]
        ]
    }

    private func resourceAttributes() -> [[String: Any]] {
        var attrs: [String: OTLPAttributeValue] = [
            "service.name": .string("OpenPPP2"),
            "service.version": .string(appVersion),
            "service.namespace": .string("openppp2"),
            "telemetry.sdk.name": .string("openppp2-ios-minimal-otlp"),
            "telemetry.sdk.language": .string("swift"),
            "os.type": .string("ios")
        ]
        for (key, value) in TelemetryIdentity.resourceAttributes {
            attrs[key] = value
        }
        if let bundleIdentifier = Bundle.main.bundleIdentifier {
            attrs["app.bundle_id"] = .string(bundleIdentifier)
        }
        return attrs.map(Self.attributeJson(key:value:)).sorted { lhs, rhs in
            (lhs["key"] as? String ?? "") < (rhs["key"] as? String ?? "")
        }
    }

    private static func logRecordJson(_ record: OTLPLogRecord) -> [String: Any] {
        [
            "timeUnixNano": String(record.timeUnixNano),
            "severityText": record.severityText,
            "body": ["stringValue": record.body],
            "attributes": record.attributes.map(attributeJson(key:value:)).sorted { lhs, rhs in
                (lhs["key"] as? String ?? "") < (rhs["key"] as? String ?? "")
            }
        ]
    }

    private static func attributeJson(key: String, value: OTLPAttributeValue) -> [String: Any] {
        [
            "key": key,
            "value": value.jsonValue
        ]
    }

    private static func logsURL(from endpoint: String) -> URL? {
        let trimmed = endpoint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        guard var components = URLComponents(string: trimmed),
              components.scheme == "http" || components.scheme == "https",
              components.host?.isEmpty == false
        else {
            return nil
        }

        let path = components.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        if path.isEmpty {
            components.path = "/v1/logs"
        } else if path != "v1/logs" && !path.hasSuffix("/v1/logs") {
            components.path = "/" + path + "/v1/logs"
        }
        return components.url
    }

    private var appVersion: String {
        let short = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "0"
        return "\(short)+\(build)"
    }
}
