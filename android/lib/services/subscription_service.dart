import 'dart:convert';
import 'dart:io';

import '../models/remote_subscription.dart';

class SubscriptionService {
  static const int maxBytes = 2 * 1024 * 1024;

  Future<RemoteSubscriptionResult> fetch(String urlText) async {
    final uri = Uri.tryParse(urlText.trim());
    if (uri == null || (uri.scheme != 'https' && uri.scheme != 'http')) {
      throw const FormatException('订阅地址必须是 http 或 https URL');
    }

    final client = HttpClient();
    client.connectionTimeout = const Duration(seconds: 12);
    try {
      final request = await client.getUrl(uri);
      request.headers.set(HttpHeaders.acceptHeader, 'application/json');
      request.headers.set(HttpHeaders.userAgentHeader, 'OpenPPP2/Android');
      final response = await request.close();
      if (response.statusCode < 200 || response.statusCode >= 300) {
        throw HttpException('订阅请求失败: HTTP ${response.statusCode}');
      }

      final chunks = <int>[];
      await for (final chunk in response) {
        chunks.addAll(chunk);
        if (chunks.length > maxBytes) {
          throw const FormatException('订阅响应超过 2MB');
        }
      }
      return RemoteSubscriptionParser.parse(utf8.decode(chunks));
    } finally {
      client.close(force: true);
    }
  }
}
