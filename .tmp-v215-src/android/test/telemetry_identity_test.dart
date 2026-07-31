import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:openppp2_mobile/services/telemetry_identity.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('supersocksr.ppp/vpn');

  setUp(() {
    TelemetryIdentity.clearCacheForTest();
  });

  tearDown(() {
    TelemetryIdentity.clearCacheForTest();
  });

  group('TelemetryIdentity', () {
    test('machineId reads native payload once and caches result', () async {
      var calls = 0;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
        if (call.method == 'getTelemetryIdentity') {
          calls++;
          return {
            'machineId': 'abc123def456',
            'resourceAttributes': {
              'machine.id': 'abc123def456',
              'device.model': 'shiba',
              'os.name': 'Android',
              'os.version': '14',
            },
          };
        }
        return null;
      });

      expect(await TelemetryIdentity.machineId(), 'abc123def456');
      expect(await TelemetryIdentity.machineId(), 'abc123def456');
      expect(calls, 1);
    });

    test('resourceAttributes maps native payload to string map', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
        if (call.method == 'getTelemetryIdentity') {
          return {
            'machineId': 'deadbeef',
            'resourceAttributes': {
              'machine.id': 'deadbeef',
              'device.family': 'phone',
              'device.vendor_id_hash': 'vendorhash',
            },
          };
        }
        return null;
      });

      final attrs = await TelemetryIdentity.resourceAttributes();
      expect(attrs['machine.id'], 'deadbeef');
      expect(attrs['device.family'], 'phone');
      expect(attrs['device.vendor_id_hash'], 'vendorhash');
    });

    test('returns empty values when platform channel fails', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
        throw PlatformException(code: 'UNAVAILABLE');
      });

      expect(await TelemetryIdentity.machineId(), '');
      expect(await TelemetryIdentity.resourceAttributes(), isEmpty);
    });

    test('installIfNeeded triggers identity load', () async {
      var loaded = false;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
        if (call.method == 'getTelemetryIdentity') {
          loaded = true;
          return {'machineId': 'x', 'resourceAttributes': {}};
        }
        return null;
      });

      await TelemetryIdentity.installIfNeeded();
      expect(loaded, isTrue);
    });
  });
}
