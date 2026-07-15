import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:openppp2_mobile/runtime/runtime_bridge.dart';
import 'package:openppp2_mobile/runtime/runtime_snapshot.dart';

Map<String, dynamic> readFixture(String name) {
  final text = File('../tests/contracts/runtime-snapshot/$name').readAsStringSync();
  return jsonDecode(text) as Map<String, dynamic>;
}

void main() {
  test('all canonical fixtures decode', () {
    final phases = <String, RuntimePhase>{
      'idle.json': RuntimePhase.idle,
      'connected.json': RuntimePhase.connected,
      'reconnecting.json': RuntimePhase.reconnecting,
      'failed.json': RuntimePhase.failed,
    };
    for (final entry in phases.entries) {
      expect(RuntimeSnapshot.fromJson(readFixture(entry.key)).phase, entry.value);
    }
  });

  test('connected fixture decodes effective mode and ignores future fields', () {
    final snapshot = RuntimeSnapshot.fromJson(readFixture('connected.json'));
    expect(snapshot.generation, 7);
    expect(snapshot.phase, RuntimePhase.connected);
    expect(snapshot.requestedMuxMode, 'flow');
    expect(snapshot.effectiveMuxMode, 'flow');
    expect(snapshot.muxReceiverOrdering, 'flow_v2');
    expect(snapshot.muxActiveLinks, 2);
    expect(snapshot.capabilities, containsAll(<String>[
      'mux.compat',
      'mux.flow',
      'mux.balance',
      'mux.stripe',
    ]));
  });

  test('VMUX selector is capability driven and hides stripe normally', () {
    final snapshot = RuntimeSnapshot.fromJson(readFixture('connected.json'));
    expect(snapshot.availableMuxModes(), <String>['compat', 'flow', 'balance']);
    expect(
      snapshot.availableMuxModes(experimental: true),
      <String>['compat', 'flow', 'balance', 'stripe'],
    );
  });

  test('fallback presentation separates normal and diagnostic detail', () {
    final snapshot = RuntimeSnapshot.fromJson(readFixture('reconnecting.json'));
    expect(snapshot.effectiveMuxDisplayName, 'Compatibility mode');
    expect(snapshot.muxDiagnosticLines, contains('Requested VMUX: balance'));
    expect(
      snapshot.muxDiagnosticLines,
      contains('Fallback reason: peer_missing_flow_v2'),
    );
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

  test('unsupported schema still exposes ordering metadata', () {
    final ordering = decodeRuntimeOrdering(
      jsonEncode(readFixture('unsupported-schema.json')),
    );
    expect(ordering.generation, 1);
    expect(ordering.monotonicMs, 1);
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

  test('missing capabilities uses bundled schema-v1 compatibility fallback', () {
    final snapshot = RuntimeSnapshot.fromJson(<String, dynamic>{
      'schema_version': 1,
      'generation': 1,
      'monotonic_ms': 1,
      'phase': 'idle',
    });
    expect(snapshot.capabilities, RuntimeSnapshot.bundledCapabilities);
  });

  test('explicit empty capabilities does not guess support', () {
    final snapshot = RuntimeSnapshot.fromJson(<String, dynamic>{
      'schema_version': 1,
      'generation': 1,
      'monotonic_ms': 1,
      'phase': 'idle',
      'capabilities': <String>[],
    });
    expect(snapshot.capabilities, isEmpty);
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
