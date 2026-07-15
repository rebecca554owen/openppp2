enum RuntimePhase {
  idle,
  starting,
  preparingHost,
  connecting,
  handshaking,
  applyingPolicy,
  connected,
  reconnecting,
  stopping,
  failed,
  unknown;

  static RuntimePhase parse(String value) {
    switch (value) {
      case 'idle':
        return RuntimePhase.idle;
      case 'starting':
        return RuntimePhase.starting;
      case 'preparing_host':
        return RuntimePhase.preparingHost;
      case 'connecting':
        return RuntimePhase.connecting;
      case 'handshaking':
        return RuntimePhase.handshaking;
      case 'applying_policy':
        return RuntimePhase.applyingPolicy;
      case 'connected':
        return RuntimePhase.connected;
      case 'reconnecting':
        return RuntimePhase.reconnecting;
      case 'stopping':
        return RuntimePhase.stopping;
      case 'failed':
        return RuntimePhase.failed;
      case 'unknown':
        return RuntimePhase.unknown;
      default:
        throw FormatException('Unknown runtime phase: $value');
    }
  }
}

class RuntimeErrorSnapshot {
  const RuntimeErrorSnapshot({
    this.code = 0,
    this.severity = '',
    this.retryable = false,
    this.userMessageKey = '',
    this.diagnosticDetail = '',
  });

  final int code;
  final String severity;
  final bool retryable;
  final String userMessageKey;
  final String diagnosticDetail;

  factory RuntimeErrorSnapshot.fromJson(Map<String, dynamic>? json) {
    if (json == null) return const RuntimeErrorSnapshot();
    return RuntimeErrorSnapshot(
      code: json['code'] as int? ?? 0,
      severity: json['severity'] as String? ?? '',
      retryable: json['retryable'] as bool? ?? false,
      userMessageKey: json['user_message_key'] as String? ?? '',
      diagnosticDetail: json['diagnostic_detail'] as String? ?? '',
    );
  }
}

class RuntimeSnapshot {
  const RuntimeSnapshot({
    required this.generation,
    required this.monotonicMs,
    required this.phase,
    this.role = '',
    this.server = '',
    this.transport = '',
    this.requestedMuxMode = '',
    this.effectiveMuxMode = '',
    this.muxReceiverOrdering = '',
    this.muxActiveLinks = 0,
    this.muxFallbackReason = '',
    this.p2pState = '',
    this.effectivePath = '',
    this.lastError = const RuntimeErrorSnapshot(),
  });

  static const int schemaVersion = 1;

  final int generation;
  final int monotonicMs;
  final RuntimePhase phase;
  final String role;
  final String server;
  final String transport;
  final String requestedMuxMode;
  final String effectiveMuxMode;
  final String muxReceiverOrdering;
  final int muxActiveLinks;
  final String muxFallbackReason;
  final String p2pState;
  final String effectivePath;
  final RuntimeErrorSnapshot lastError;

  factory RuntimeSnapshot.fromJson(Map<String, dynamic> json) {
    final version = json['schema_version'];
    if (version != schemaVersion) {
      throw FormatException('Unsupported runtime schema version: $version');
    }
    final generation = json['generation'];
    if (generation is! int || generation < 0) {
      throw const FormatException('Runtime generation is required');
    }
    final monotonicMs = json['monotonic_ms'];
    if (monotonicMs is! int || monotonicMs < 0) {
      throw const FormatException('Runtime monotonic_ms is required');
    }
    final phaseValue = json['phase'];
    if (phaseValue is! String) {
      throw const FormatException('Runtime phase is required');
    }

    return RuntimeSnapshot(
      generation: generation,
      monotonicMs: monotonicMs,
      phase: RuntimePhase.parse(phaseValue),
      role: json['role'] as String? ?? '',
      server: json['server'] as String? ?? '',
      transport: json['transport'] as String? ?? '',
      requestedMuxMode: json['requested_mux_mode'] as String? ?? '',
      effectiveMuxMode: json['effective_mux_mode'] as String? ?? '',
      muxReceiverOrdering: json['mux_receiver_ordering'] as String? ?? '',
      muxActiveLinks: json['mux_active_links'] as int? ?? 0,
      muxFallbackReason: json['mux_fallback_reason'] as String? ?? '',
      p2pState: json['p2p_state'] as String? ?? '',
      effectivePath: json['effective_path'] as String? ?? '',
      lastError: RuntimeErrorSnapshot.fromJson(
        json['last_error'] as Map<String, dynamic>?,
      ),
    );
  }
}
