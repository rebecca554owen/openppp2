import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:openppp2_mobile/models/telemetry_settings.dart';
import 'package:openppp2_mobile/services/profile_store.dart';

void main() {
  group('ProfileStore.effectiveJson telemetry', () {
    const profileJson = '''
{
  "server": {
    "host": "example.com",
    "port": 20000
  }
}
''';

    test('injects telemetry block from TelemetrySettings', () {
      const telemetry = TelemetrySettings(
        uploadEnabled: true,
        destination: TelemetryDestination.custom,
        customEndpoint: 'https://otel.example.com',
        includeNativeTelemetry: true,
        nativeLogLevel: 2,
        nativeSpansEnabled: true,
      );

      final merged = ProfileStore.effectiveJson(
        profileJson,
        const {},
        telemetry: telemetry,
      );
      final root = jsonDecode(merged) as Map<String, dynamic>;
      final block = root['telemetry'] as Map<String, dynamic>;

      expect(block['enabled'], isTrue);
      expect(block['level'], 2);
      expect(block['span'], isTrue);
      expect(block['endpoint'], 'https://otel.example.com');
      expect(block['console-log'], isTrue);
    });

    test('default telemetry preset disables native telemetry in merged JSON', () {
      final merged = ProfileStore.effectiveJson(profileJson, const {});
      final root = jsonDecode(merged) as Map<String, dynamic>;
      final block = root['telemetry'] as Map<String, dynamic>;

      expect(block['enabled'], isFalse);
      expect(block['endpoint'], '');
    });

    test('overwrites any pre-existing telemetry section in profile JSON', () {
      const profileWithTelemetry = '''
{
  "server": {"host": "example.com"},
  "telemetry": {
    "enabled": true,
    "endpoint": "https://old.example.com"
  }
}
''';

      final merged = ProfileStore.effectiveJson(
        profileWithTelemetry,
        const {},
        telemetry: TelemetrySettings.disabled,
      );
      final root = jsonDecode(merged) as Map<String, dynamic>;
      final block = root['telemetry'] as Map<String, dynamic>;

      expect(block['enabled'], isFalse);
      expect(block['endpoint'], '');
    });
    test('dns intercept-unmatched stays true when saved options omit the key', () {
      final merged = ProfileStore.effectiveJson(
        ProfileStore.defaultJson,
        const {
          'dnsConfig': {
            'domestic': 'doh.pub',
            'foreign': 'cloudflare',
          },
        },
      );
      final root = jsonDecode(merged) as Map<String, dynamic>;
      final dns = root['dns'] as Map<String, dynamic>;

      expect(dns['intercept-unmatched'], isTrue);
      final ecs = dns['ecs'] as Map<String, dynamic>;
      expect(ecs['enabled'], isTrue);
      final tls = dns['tls'] as Map<String, dynamic>;
      expect(tls['verify-peer'], isTrue);
    });
  });
}
