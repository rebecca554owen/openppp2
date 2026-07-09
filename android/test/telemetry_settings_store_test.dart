import 'package:flutter_test/flutter_test.dart';
import 'package:openppp2_mobile/models/telemetry_settings.dart';
import 'package:openppp2_mobile/services/telemetry_settings_store.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('TelemetrySettingsStore', () {
    setUp(() async {
      SharedPreferences.setMockInitialValues({});
    });

    test('settings returns defaults when nothing persisted', () async {
      final store = TelemetrySettingsStore();
      final settings = await store.settings();
      expect(settings.uploadEnabled, isFalse);
      expect(settings.destination, TelemetryDestination.developer);
    });

    test('save persists settings and emits change stream', () async {
      final store = TelemetrySettingsStore();
      final changes = <int>[];
      final sub = store.changes.listen((_) => changes.add(1));

      const next = TelemetrySettings(
        uploadEnabled: true,
        destination: TelemetryDestination.custom,
        customEndpoint: 'https://otel.example.com',
        nativeLogLevel: 2,
        nativeSpansEnabled: true,
      );
      await store.save(next);

      final loaded = await store.settings();
      expect(loaded.uploadEnabled, isTrue);
      expect(loaded.customEndpoint, 'https://otel.example.com');
      expect(loaded.nativeLogLevel, 2);
      expect(loaded.nativeSpansEnabled, isTrue);
      expect(changes, [1]);

      await sub.cancel();
    });

    test('settings tolerates corrupt persisted JSON', () async {
      SharedPreferences.setMockInitialValues({
        'openppp2_telemetry_settings_v1': '{not json',
      });

      final store = TelemetrySettingsStore();
      final settings = await store.settings();
      expect(settings.uploadEnabled, isFalse);
    });
  });
}
