/// OpenTelemetry / native telemetry settings (aligned with iOS TelemetrySettings).
class TelemetrySettings {
  final bool uploadEnabled;
  final TelemetryDestination destination;
  final String customEndpoint;
  final bool includeCrashReports;
  final bool includeNativeTelemetry;
  final int nativeLogLevel;
  final bool nativeMetricsEnabled;
  final bool nativeSpansEnabled;

  const TelemetrySettings({
    this.uploadEnabled = false,
    this.destination = TelemetryDestination.developer,
    this.customEndpoint = '',
    this.includeCrashReports = true,
    this.includeNativeTelemetry = true,
    this.nativeLogLevel = 1,
    this.nativeMetricsEnabled = false,
    this.nativeSpansEnabled = false,
  });

  /// Developer-default OTLP URL (aligned with iOS `OpenPPP2TelemetryDeveloperEndpoint`).
  static const String _defaultDeveloperEndpoint =
      'https://otel-openppp2.ling.com.es/openppp2-cb7847ae-91bd-459b-b2b4-a7fa506fa4d6/v1/logs';

  /// Optional developer-default OTLP base URL (overridable at build time).
  static const String developerEndpoint = String.fromEnvironment(
    'OPENPPP2_TELEMETRY_DEVELOPER_ENDPOINT',
    defaultValue: _defaultDeveloperEndpoint,
  );

  String get effectiveEndpoint {
    switch (destination) {
      case TelemetryDestination.developer:
        return developerEndpoint.trim();
      case TelemetryDestination.custom:
        return customEndpoint.trim();
    }
  }

  bool get canUpload => uploadEnabled && effectiveEndpoint.isNotEmpty;

  static const disabled = TelemetrySettings(
    uploadEnabled: false,
    includeCrashReports: false,
    includeNativeTelemetry: false,
  );

  Map<String, dynamic> toMap() => {
        'uploadEnabled': uploadEnabled,
        'destination': destination.name,
        'customEndpoint': customEndpoint,
        'includeCrashReports': includeCrashReports,
        'includeNativeTelemetry': includeNativeTelemetry,
        'nativeLogLevel': nativeLogLevel,
        'nativeMetricsEnabled': nativeMetricsEnabled,
        'nativeSpansEnabled': nativeSpansEnabled,
      };

  factory TelemetrySettings.fromMap(Map<String, dynamic> m) {
    final destRaw = (m['destination'] ?? 'developer').toString();
    return TelemetrySettings(
      uploadEnabled: m['uploadEnabled'] == true,
      destination: TelemetryDestination.values.firstWhere(
        (d) => d.name == destRaw,
        orElse: () => TelemetryDestination.developer,
      ),
      customEndpoint: (m['customEndpoint'] ?? '').toString(),
      includeCrashReports: m['includeCrashReports'] != false,
      includeNativeTelemetry: m['includeNativeTelemetry'] != false,
      nativeLogLevel: (m['nativeLogLevel'] is int) ? m['nativeLogLevel'] as int : 1,
      nativeMetricsEnabled: m['nativeMetricsEnabled'] == true,
      nativeSpansEnabled: m['nativeSpansEnabled'] == true,
    );
  }

  TelemetrySettings copyWith({
    bool? uploadEnabled,
    TelemetryDestination? destination,
    String? customEndpoint,
    bool? includeCrashReports,
    bool? includeNativeTelemetry,
    int? nativeLogLevel,
    bool? nativeMetricsEnabled,
    bool? nativeSpansEnabled,
  }) =>
      TelemetrySettings(
        uploadEnabled: uploadEnabled ?? this.uploadEnabled,
        destination: destination ?? this.destination,
        customEndpoint: customEndpoint ?? this.customEndpoint,
        includeCrashReports: includeCrashReports ?? this.includeCrashReports,
        includeNativeTelemetry:
            includeNativeTelemetry ?? this.includeNativeTelemetry,
        nativeLogLevel: nativeLogLevel ?? this.nativeLogLevel,
        nativeMetricsEnabled:
            nativeMetricsEnabled ?? this.nativeMetricsEnabled,
        nativeSpansEnabled: nativeSpansEnabled ?? this.nativeSpansEnabled,
      );

  /// OTLP logs URL derived from the configured HTTP endpoint.
  static String? logsUrl(String endpoint) {
    final trimmed = endpoint.trim();
    if (trimmed.isEmpty) return null;
    final uri = Uri.tryParse(trimmed);
    if (uri == null) return null;
    final scheme = uri.scheme.toLowerCase();
    if (scheme != 'http' && scheme != 'https') return null;
    if (uri.host.isEmpty) return null;
    final path = uri.path.replaceAll(RegExp(r'^/+|/+$'), '');
    if (path.isEmpty) {
      return uri.replace(path: '/v1/logs').toString();
    }
    if (path == 'v1/logs' || path.endsWith('/v1/logs')) {
      return uri.toString();
    }
    return uri.replace(path: '${uri.path}/v1/logs').toString();
  }

  /// Native engine telemetry endpoint (base URL, not /v1/logs).
  static String? nativeEngineEndpoint(TelemetrySettings settings) {
    if (!settings.uploadEnabled || !settings.includeNativeTelemetry) {
      return null;
    }
    final endpoint = settings.effectiveEndpoint;
    final uri = Uri.tryParse(endpoint);
    if (uri == null) return null;
    final scheme = uri.scheme.toLowerCase();
    if (scheme != 'http' && scheme != 'https') return null;
    if (uri.host.isEmpty) return null;
    return endpoint;
  }

  /// Build the `telemetry` object merged into AppConfiguration JSON.
  static Map<String, dynamic> appConfigurationBlock(TelemetrySettings settings) {
    final endpoint = nativeEngineEndpoint(settings);
    return {
      'enabled': settings.uploadEnabled && settings.includeNativeTelemetry,
      'level': settings.nativeLogLevel,
      'count': settings.nativeMetricsEnabled,
      'span': settings.nativeSpansEnabled,
      'console-log': true,
      'console-metric': settings.nativeMetricsEnabled,
      'console-span': settings.nativeSpansEnabled,
      'endpoint': endpoint ?? '',
      'log-file': '',
    };
  }
}

enum TelemetryDestination {
  developer,
  custom;

  String get label {
    switch (this) {
      case TelemetryDestination.developer:
        return '开发者默认';
      case TelemetryDestination.custom:
        return '自定义';
    }
  }
}
