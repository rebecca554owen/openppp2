import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:openppp2_mobile/services/subscription_service.dart';

const _validSubscription = '''{
  "type": "openppp2-subscription",
  "version": 1,
  "nodes": [
    {
      "id": "test-node",
      "name": "Test Node",
      "config": {"client": {"server": "ppp://127.0.0.1:20000"}}
    }
  ]
}''';

Future<HttpServer> _serve(
  FutureOr<void> Function(HttpRequest request) handler,
) async {
  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  server.listen(handler);
  return server;
}

String _url(HttpServer server, [String path = '/subscription.json']) =>
    'http://127.0.0.1:${server.port}$path';

void main() {
  test('fetches a valid loopback subscription', () async {
    final server = await _serve((request) async {
      request.response.headers.contentType = ContentType.json;
      request.response.write(_validSubscription);
      await request.response.close();
    });
    addTearDown(() => server.close(force: true));

    final result = await SubscriptionService().fetch(_url(server));

    expect(result.nodes, hasLength(1));
    expect(result.nodes.single.id, 'test-node');
  });

  test('times out while waiting for response headers', () async {
    final server = await _serve((_) {});
    addTearDown(() => server.close(force: true));

    final future = SubscriptionService(
      requestTimeout: const Duration(milliseconds: 100),
    ).fetch(_url(server));

    await expectLater(future, throwsA(isA<TimeoutException>()));
  });

  test('times out while reading the response body', () async {
    final server = await _serve((request) {
      request.response.statusCode = HttpStatus.ok;
      request.response.write('{');
    });
    addTearDown(() => server.close(force: true));

    final future = SubscriptionService(
      requestTimeout: const Duration(milliseconds: 100),
    ).fetch(_url(server));

    await expectLater(future, throwsA(isA<TimeoutException>()));
  });

  test('times out while draining a redirect response', () async {
    final server = await _serve((request) {
      request.response.statusCode = HttpStatus.found;
      request.response.headers.set(HttpHeaders.locationHeader, '/next.json');
      request.response.write('redirecting');
    });
    addTearDown(() => server.close(force: true));

    final future = SubscriptionService(
      requestTimeout: const Duration(milliseconds: 100),
    ).fetch(_url(server));

    await expectLater(future, throwsA(isA<TimeoutException>()));
  });
}
