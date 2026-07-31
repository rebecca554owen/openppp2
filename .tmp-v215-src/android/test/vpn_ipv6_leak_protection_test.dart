import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('Android VPN service captures IPv6 to prevent leaks', () {
    final service = File('android/app/src/main/kotlin/supersocksr/ppp/android/PppVpnService.kt').readAsStringSync();

    expect(service, contains('IPV6_BLOCK_ADDRESS = "fd00:6f70:656e:7070::2"'));
    expect(service, contains('builder.addAddress(IPV6_BLOCK_ADDRESS, 128)'));
    expect(service, contains('builder.addRoute("::", 0)'));
    expect(service, contains('builder.allowFamily(OsConstants.AF_INET6)'));
    expect(service, contains('IPv6 leak protection setup failed'));
  });
}
