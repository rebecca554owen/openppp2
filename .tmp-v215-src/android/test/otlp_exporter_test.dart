import 'package:flutter_test/flutter_test.dart';
import 'package:openppp2_mobile/models/telemetry_settings.dart';
import 'package:openppp2_mobile/services/otlp_exporter.dart';

void main() {
  group('OtlpExporter', () {
    test('throws when upload is disabled', () async {
      const settings = TelemetrySettings(
        destination: TelemetryDestination.custom,
        customEndpoint: 'https://otel.example.com',
      );

      await expectLater(
        OtlpExporter.exportLogs(
          settings: settings,
          records: const [
            OtlpLogRecord(
              timeUnixNano: 1,
              severityText: 'INFO',
              body: 'test',
            ),
          ],
        ),
        throwsA(
          isA<OtlpExportException>().having(
            (e) => e.message,
            'message',
            '遥测上传未开启',
          ),
        ),
      );
    });

    test('returns without network when records are empty', () async {
      const settings = TelemetrySettings(
        uploadEnabled: true,
        destination: TelemetryDestination.custom,
        customEndpoint: 'https://otel.example.com',
      );

      await expectLater(
        OtlpExporter.exportLogs(settings: settings, records: const []),
        completes,
      );
    });

    test('throws when endpoint cannot produce OTLP logs URL', () async {
      const settings = TelemetrySettings(
        uploadEnabled: true,
        destination: TelemetryDestination.custom,
        customEndpoint: 'not-a-valid-url',
      );

      await expectLater(
        OtlpExporter.exportLogs(
          settings: settings,
          records: const [
            OtlpLogRecord(
              timeUnixNano: 1,
              severityText: 'INFO',
              body: 'test',
            ),
          ],
        ),
        throwsA(
          isA<OtlpExportException>().having(
            (e) => e.message,
            'message',
            'OpenTelemetry endpoint 无效',
          ),
        ),
      );
    });
  });
}
