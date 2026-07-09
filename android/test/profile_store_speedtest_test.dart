import 'package:flutter_test/flutter_test.dart';
import 'package:openppp2_mobile/services/profile_store.dart';

void main() {
  group('ProfileStore speedtest defaults', () {
    test('ensureSpeedtestDnsRules appends missing Ookla domains', () {
      const existing = 'google.com /cloudflare/tun';
      final merged = ProfileStore.ensureSpeedtestDnsRules(existing);
      expect(merged, contains('google.com /cloudflare/tun'));
      expect(merged, contains('speedtest.net'));
      expect(merged, contains('ookla.com'));
      expect(merged, contains('ooklaserver.net'));
      expect(merged, contains('cdnst.net'));
    });

    test('ensureSpeedtestDnsRules is idempotent', () {
      const merged = ProfileStore.defaultSpeedtestDnsRules;
      expect(ProfileStore.ensureSpeedtestDnsRules(merged), merged);
    });

    test('patchOptionsForSpeedtest enables static mode and relaxes QUIC block', () {
      final patched = ProfileStore.patchOptionsForSpeedtest({
        'staticMode': false,
        'blockQuic': true,
        'dnsRulesList': '',
      });
      expect(patched['staticMode'], isTrue);
      expect(patched['blockQuic'], isFalse);
      expect(patched['dnsRulesList'], contains('speedtest.net'));
    });
  });
}
