import 'dart:convert';

import 'runtime_snapshot.dart';

RuntimeSnapshot decodeRuntimeSnapshot(String payload) {
  final decoded = jsonDecode(payload);
  if (decoded is! Map<String, dynamic>) {
    throw const FormatException('Runtime snapshot must be a JSON object');
  }
  return RuntimeSnapshot.fromJson(decoded);
}
