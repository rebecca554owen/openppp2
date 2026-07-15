import Foundation

public enum RuntimePhase: String, Codable, Sendable {
    case idle
    case starting
    case preparingHost = "preparing_host"
    case connecting
    case handshaking
    case applyingPolicy = "applying_policy"
    case connected
    case reconnecting
    case stopping
    case failed
    case unknown
}

public struct RuntimeErrorSnapshot: Codable, Equatable, Sendable {
    public var code: UInt32
    public var severity: String
    public var retryable: Bool
    public var userMessageKey: String
    public var diagnosticDetail: String

    public init(
        code: UInt32 = 0,
        severity: String = "",
        retryable: Bool = false,
        userMessageKey: String = "",
        diagnosticDetail: String = ""
    ) {
        self.code = code
        self.severity = severity
        self.retryable = retryable
        self.userMessageKey = userMessageKey
        self.diagnosticDetail = diagnosticDetail
    }

    enum CodingKeys: String, CodingKey {
        case code
        case severity
        case retryable
        case userMessageKey = "user_message_key"
        case diagnosticDetail = "diagnostic_detail"
    }
}

public struct RuntimeSnapshot: Codable, Equatable, Sendable {
    public static let schemaVersion: UInt32 = 1

    public var generation: UInt64
    public var monotonicMs: UInt64
    public var phase: RuntimePhase
    public var role: String
    public var server: String
    public var transport: String
    public var requestedMuxMode: String
    public var effectiveMuxMode: String
    public var muxReceiverOrdering: String
    public var muxActiveLinks: UInt16
    public var muxFallbackReason: String
    public var p2pState: String
    public var effectivePath: String
    public var lastError: RuntimeErrorSnapshot

    public init(
        generation: UInt64,
        monotonicMs: UInt64,
        phase: RuntimePhase,
        role: String = "",
        server: String = "",
        transport: String = "",
        requestedMuxMode: String = "",
        effectiveMuxMode: String = "",
        muxReceiverOrdering: String = "",
        muxActiveLinks: UInt16 = 0,
        muxFallbackReason: String = "",
        p2pState: String = "",
        effectivePath: String = "",
        lastError: RuntimeErrorSnapshot = RuntimeErrorSnapshot()
    ) {
        self.generation = generation
        self.monotonicMs = monotonicMs
        self.phase = phase
        self.role = role
        self.server = server
        self.transport = transport
        self.requestedMuxMode = requestedMuxMode
        self.effectiveMuxMode = effectiveMuxMode
        self.muxReceiverOrdering = muxReceiverOrdering
        self.muxActiveLinks = muxActiveLinks
        self.muxFallbackReason = muxFallbackReason
        self.p2pState = p2pState
        self.effectivePath = effectivePath
        self.lastError = lastError
    }

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case generation
        case monotonicMs = "monotonic_ms"
        case phase
        case role
        case server
        case transport
        case requestedMuxMode = "requested_mux_mode"
        case effectiveMuxMode = "effective_mux_mode"
        case muxReceiverOrdering = "mux_receiver_ordering"
        case muxActiveLinks = "mux_active_links"
        case muxFallbackReason = "mux_fallback_reason"
        case p2pState = "p2p_state"
        case effectivePath = "effective_path"
        case lastError = "last_error"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let version = try container.decode(UInt32.self, forKey: .schemaVersion)
        guard version == Self.schemaVersion else {
            throw DecodingError.dataCorruptedError(
                forKey: .schemaVersion,
                in: container,
                debugDescription: "Unsupported runtime schema version: \(version)"
            )
        }

        generation = try container.decode(UInt64.self, forKey: .generation)
        monotonicMs = try container.decode(UInt64.self, forKey: .monotonicMs)
        phase = try container.decode(RuntimePhase.self, forKey: .phase)
        role = try container.decodeIfPresent(String.self, forKey: .role) ?? ""
        server = try container.decodeIfPresent(String.self, forKey: .server) ?? ""
        transport = try container.decodeIfPresent(String.self, forKey: .transport) ?? ""
        requestedMuxMode = try container.decodeIfPresent(String.self, forKey: .requestedMuxMode) ?? ""
        effectiveMuxMode = try container.decodeIfPresent(String.self, forKey: .effectiveMuxMode) ?? ""
        muxReceiverOrdering = try container.decodeIfPresent(String.self, forKey: .muxReceiverOrdering) ?? ""
        muxActiveLinks = try container.decodeIfPresent(UInt16.self, forKey: .muxActiveLinks) ?? 0
        muxFallbackReason = try container.decodeIfPresent(String.self, forKey: .muxFallbackReason) ?? ""
        p2pState = try container.decodeIfPresent(String.self, forKey: .p2pState) ?? ""
        effectivePath = try container.decodeIfPresent(String.self, forKey: .effectivePath) ?? ""
        lastError = try container.decodeIfPresent(RuntimeErrorSnapshot.self, forKey: .lastError) ?? RuntimeErrorSnapshot()
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(Self.schemaVersion, forKey: .schemaVersion)
        try container.encode(generation, forKey: .generation)
        try container.encode(monotonicMs, forKey: .monotonicMs)
        try container.encode(phase, forKey: .phase)
        try container.encode(role, forKey: .role)
        try container.encode(server, forKey: .server)
        try container.encode(transport, forKey: .transport)
        try container.encode(requestedMuxMode, forKey: .requestedMuxMode)
        try container.encode(effectiveMuxMode, forKey: .effectiveMuxMode)
        try container.encode(muxReceiverOrdering, forKey: .muxReceiverOrdering)
        try container.encode(muxActiveLinks, forKey: .muxActiveLinks)
        try container.encode(muxFallbackReason, forKey: .muxFallbackReason)
        try container.encode(p2pState, forKey: .p2pState)
        try container.encode(effectivePath, forKey: .effectivePath)
        try container.encode(lastError, forKey: .lastError)
    }
}
