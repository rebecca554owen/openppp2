import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:openppp2_mobile/runtime/runtime_snapshot.dart';

Map<String, dynamic> readFixture(String name) {
  final text = File('../tests/contracts/runtime-snapshot/$name').readAsStringSync();
  return jsonDecode(text) as Map<String, dynamic>;
}

void main() {
  test('connected fixture decodes effective mode and ignores future fields', () {
    final snapshot = RuntimeSnapshot.fromJson(readFixture('connected.json'));
    expect(snapshot.generation, 7);
    expect(snapshot.phase, RuntimePhase.connected);
    expect(snapshot.requestedMuxMode, 'flow');
    expect(snapshot.effectiveMuxMode, 'flow');
  });

  test('failed fixture decodes structured error', () {
    final snapshot = RuntimeSnapshot.fromJson(readFixture('failed.json'));
    expect(snapshot.phase, RuntimePhase.failed);
    expect(snapshot.lastError.code, 1001);
    expect(snapshot.lastError.retryable, isTrue);
    expect(snapshot.lastError.userMessageKey, 'connection.tunnel_open_failed');
  });

  test('unsupported schema is rejected', () {
    expect(
      () => RuntimeSnapshot.fromJson(readFixture('unsupported-schema.json')),
      throwsFormatException,
    );
  });

  test('unknown runtime phase is rejected', () {
    expect(
      () => RuntimeSnapshot.fromJson({
        'schema_version': 1,
        'generation': 1,
        'monotonic_ms': 1,
        'phase': 'teleporting',
      }),
      throwsFormatException,
    );
  });

  test('generation and monotonic time are required', () {
    expect(
      () => RuntimeSnapshot.fromJson({
        'schema_version': 1,
        'monotonic_ms': 1,
        'phase': 'idle',
      }),
      throwsFormatException,
    );
    expect(
      () => RuntimeSnapshot.fromJson({
        'schema_version': 1,
        'generation': 1,
        'phase': 'idle',
      }),
      throwsFormatException,
    );
  });
}
