import 'package:flutter_test/flutter_test.dart';
import 'package:openppp2_mobile/utils/server_endpoint.dart';

void main() {
  group('ServerEndpoint', () {
    test('parses bracketed IPv6 server URLs', () {
      final endpoint = ServerEndpoint.parse('ppp://[2001:db8::1]:20000/');

      expect(endpoint.host, '2001:db8::1');
      expect(endpoint.port, 20000);
    });

    test('parses legacy unbracketed IPv6 server URLs', () {
      final endpoint = ServerEndpoint.parse('ppp://2001:db8::1:20000/');

      expect(endpoint.host, '2001:db8::1');
      expect(endpoint.port, 20000);
    });

    test('preserves legacy unbracketed IPv6 server URLs without ports', () {
      final endpoint = ServerEndpoint.parse('ppp://2001:db8::1/');

      expect(endpoint.host, '2001:db8::1');
      expect(endpoint.port, isNull);
    });

    test('parses legacy unbracketed IPv4-mapped IPv6 server URLs', () {
      final endpoint = ServerEndpoint.parse('ppp://::ffff:192.0.2.128:20000/');

      expect(endpoint.host, '::ffff:192.0.2.128');
      expect(endpoint.port, 20000);
    });

    test('formats IPv6 host with brackets for URLs', () {
      final url = ServerEndpoint(host: '2001:db8::1', port: 20000).toPppUrl();

      expect(url, 'ppp://[2001:db8::1]:20000/');
    });

    test('formats IPv4 and domain hosts without brackets', () {
      expect(ServerEndpoint(host: '192.0.2.10', port: 20000).toPppUrl(),
          'ppp://192.0.2.10:20000/');
      expect(ServerEndpoint(host: 'vpn.example.com', port: 20000).toPppUrl(),
          'ppp://vpn.example.com:20000/');
    });
  });
}
