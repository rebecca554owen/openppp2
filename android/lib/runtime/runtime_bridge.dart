import 'dart:convert';

import 'runtime_snapshot.dart';

class RuntimeOrdering {
  const RuntimeOrdering({required this.generation, required this.monotonicMs});

  final int generation;
  final int monotonicMs;
}

Map<String, dynamic> _decodeRuntimeMap(String payload) {
  final decoded = jsonDecode(payload);
  if (decoded is! Map<String, dynamic>) {
    throw const FormatException('Runtime snapshot must be a JSON object');
  }
  return decoded;
}

RuntimeSnapshot decodeRuntimeSnapshot(String payload) {
  return RuntimeSnapshot.fromJson(_decodeRuntimeMap(payload));
}

RuntimeOrdering decodeRuntimeOrdering(String payload) {
  final decoded = _decodeRuntimeMap(payload);
  final generation = decoded['generation'];
  final monotonicMs = decoded['monotonic_ms'];
  if (generation is! int || generation < 0 ||
      monotonicMs is! int || monotonicMs < 0) {
    throw const FormatException('Runtime ordering metadata is required');
  }
  return RuntimeOrdering(generation: generation, monotonicMs: monotonicMs);
}
