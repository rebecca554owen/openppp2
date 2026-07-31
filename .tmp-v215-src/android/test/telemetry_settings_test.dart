import 'package:flutter_test/flutter_test.dart';
import 'package:openppp2_mobile/models/telemetry_settings.dart';

void main() {
  group('TelemetrySettings', () {
    test('developerEndpoint matches iOS default OTLP URL', () {
      expect(TelemetrySettings.developerEndpoint, isNotEmpty);
      expect(
        TelemetrySettings.developerEndpoint,
        'https://otel-openppp2.ling.com.es/openppp2-cb7847ae-91bd-459b-b2b4-a7fa506fa4d6/v1/logs',
      );
    });

    test('canUpload requires upload flag and non-empty endpoint', () {
      const off = TelemetrySettings();
      expect(off.canUpload, isFalse);

      const customNoUrl = TelemetrySettings(
        uploadEnabled: true,
        destination: TelemetryDestination.custom,
      );
      expect(customNoUrl.canUpload, isFalse);

      const custom = TelemetrySettings(
        uploadEnabled: true,
        destination: TelemetryDestination.custom,
        customEndpoint: 'https://otel.example.com',
      );
      expect(custom.canUpload, isTrue);
    });

    test('toMap and fromMap round-trip', () {
      const original = TelemetrySettings(
        uploadEnabled: true,
        destination: TelemetryDestination.custom,
        customEndpoint: 'https://collector.example.com',
        includeCrashReports: false,
        includeNativeTelemetry: true,
        nativeLogLevel: 3,
        nativeMetricsEnabled: true,
        nativeSpansEnabled: true,
      );

      final restored = TelemetrySettings.fromMap(original.toMap());
      expect(restored.uploadEnabled, original.uploadEnabled);
      expect(restored.destination, original.destination);
      expect(restored.customEndpoint, original.customEndpoint);
      expect(restored.includeCrashReports, original.includeCrashReports);
      expect(restored.includeNativeTelemetry, original.includeNativeTelemetry);
      expect(restored.nativeLogLevel, original.nativeLogLevel);
      expect(restored.nativeMetricsEnabled, original.nativeMetricsEnabled);
      expect(restored.nativeSpansEnabled, original.nativeSpansEnabled);
    });

    test('fromMap defaults unknown destination to developer', () {
      final settings = TelemetrySettings.fromMap({
        'destination': 'unknown-dest',
      });
      expect(settings.destination, TelemetryDestination.developer);
    });

    test('logsUrl appends /v1/logs for bare collector base URL', () {
      expect(
        TelemetrySettings.logsUrl('https://otel.example.com'),
        'https://otel.example.com/v1/logs',
      );
    });

    test('logsUrl preserves endpoint that already ends with /v1/logs', () {
      const url = 'https://otel.example.com/v1/logs';
      expect(TelemetrySettings.logsUrl(url), url);
    });

    test('logsUrl rejects invalid schemes and empty hosts', () {
      expect(TelemetrySettings.logsUrl(''), isNull);
      expect(TelemetrySettings.logsUrl('ftp://otel.example.com'), isNull);
      expect(TelemetrySettings.logsUrl('not-a-url'), isNull);
    });

    test('nativeEngineEndpoint returns base URL when native telemetry enabled', () {
      const settings = TelemetrySettings(
        uploadEnabled: true,
        destination: TelemetryDestination.custom,
        customEndpoint: 'https://otel.example.com',
        includeNativeTelemetry: true,
      );
      expect(
        TelemetrySettings.nativeEngineEndpoint(settings),
        'https://otel.example.com',
      );
    });

    test('nativeEngineEndpoint is null when upload or native telemetry disabled', () {
      const uploadOff = TelemetrySettings(
        destination: TelemetryDestination.custom,
        customEndpoint: 'https://otel.example.com',
      );
      expect(TelemetrySettings.nativeEngineEndpoint(uploadOff), isNull);

      const nativeOff = TelemetrySettings(
        uploadEnabled: true,
        destination: TelemetryDestination.custom,
        customEndpoint: 'https://otel.example.com',
        includeNativeTelemetry: false,
      );
      expect(TelemetrySettings.nativeEngineEndpoint(nativeOff), isNull);
    });

    test('appConfigurationBlock mirrors iOS telemetry JSON shape', () {
      const settings = TelemetrySettings(
        uploadEnabled: true,
        destination: TelemetryDestination.custom,
        customEndpoint: 'https://otel.example.com',
        includeNativeTelemetry: true,
        nativeLogLevel: 2,
        nativeMetricsEnabled: true,
        nativeSpansEnabled: true,
      );

      expect(
        TelemetrySettings.appConfigurationBlock(settings),
        {
          'enabled': true,
          'level': 2,
          'count': true,
          'span': true,
          'console-log': true,
          'console-metric': true,
          'console-span': true,
          'endpoint': 'https://otel.example.com',
          'log-file': '',
        },
      );
    });

    test('disabled preset turns telemetry off in app configuration block', () {
      expect(
        TelemetrySettings.appConfigurationBlock(TelemetrySettings.disabled),
        {
          'enabled': false,
          'level': 1,
          'count': false,
          'span': false,
          'console-log': true,
          'console-metric': false,
          'console-span': false,
          'endpoint': '',
          'log-file': '',
        },
      );
    });
  });
}
