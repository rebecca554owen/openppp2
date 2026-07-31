import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:openppp2_mobile/models/remote_subscription.dart';

void main() {
  test('parses compact subscription nodes into full profile json', () {
    final sub = RemoteSubscriptionParser.parse(jsonEncode({
      'type': 'openppp2-subscription',
      'version': 1,
      'profilePrefix': 'Demo',
      'nodes': [
        {
          'id': 'hk-01',
          'name': 'HK 01',
          'server': 'ppp://hk.example.com:20000/',
          'key': {
            'protocol': 'aes-128-cfb',
            'protocol-key': 'p-key',
            'transport': 'aes-256-cfb',
            'transport-key': 't-key',
          },
          'options': {'mtu': 1300}
        }
      ]
    }));

    expect(sub.nodes, hasLength(1));
    expect(sub.nodes.first.id, 'hk-01');
    expect(sub.nodes.first.name, 'Demo HK 01');
    expect(sub.nodes.first.options['mtu'], 1300);

    final root = jsonDecode(sub.nodes.first.json) as Map<String, dynamic>;
    expect((root['client'] as Map)['server'], 'ppp://hk.example.com:20000/');
    expect((root['key'] as Map)['protocol-key'], 'p-key');
  });

  test('skips disabled nodes', () {
    final sub = RemoteSubscriptionParser.parse(jsonEncode({
      'type': 'openppp2-subscription',
      'version': 1,
      'nodes': [
        {
          'id': 'disabled',
          'name': 'Disabled',
          'enabled': false,
          'server': 'ppp://disabled.example.com:20000/',
          'key': {'protocol-key': 'x'}
        },
        {
          'id': 'enabled',
          'name': 'Enabled',
          'server': 'ppp://enabled.example.com:20000/',
          'key': {
            'protocol': 'aes-128-cfb',
            'protocol-key': 'p-key',
            'transport': 'aes-256-cfb',
            'transport-key': 't-key',
          }
        }
      ]
    }));

    expect(sub.nodes.map((n) => n.id), ['enabled']);
  });
}
