import 'package:flutter_test/flutter_test.dart';
import 'package:openppp2_mobile/runtime/runtime_snapshot.dart';
import 'package:openppp2_mobile/runtime/runtime_store.dart';

RuntimeSnapshot snapshot(int generation, int monotonicMs, RuntimePhase phase) {
  return RuntimeSnapshot(
    generation: generation,
    monotonicMs: monotonicMs,
    phase: phase,
  );
}

void main() {
  test('older generation cannot overwrite current state', () {
    final store =
        RuntimeStore(initial: snapshot(8, 100, RuntimePhase.connected));
    expect(store.apply(snapshot(7, 200, RuntimePhase.idle)), isFalse);
    expect(store.state.generation, 8);
    expect(store.state.phase, RuntimePhase.connected);
  });

  test('older event within the same generation is ignored', () {
    final store =
        RuntimeStore(initial: snapshot(8, 200, RuntimePhase.stopping));
    expect(store.apply(snapshot(8, 150, RuntimePhase.connected)), isFalse);
    expect(store.state.phase, RuntimePhase.stopping);
  });

  test('duplicate timestamp within the same generation is ignored', () {
    final store =
        RuntimeStore(initial: snapshot(8, 200, RuntimePhase.stopping));
    expect(store.apply(snapshot(8, 200, RuntimePhase.connected)), isFalse);
    expect(store.state.phase, RuntimePhase.stopping);
  });

  test('new generation replaces prior state', () {
    final store = RuntimeStore(initial: snapshot(8, 200, RuntimePhase.failed));
    expect(store.apply(snapshot(9, 1, RuntimePhase.starting)), isTrue);
    expect(store.state.generation, 9);
    expect(store.state.phase, RuntimePhase.starting);
  });

  test('invalid or unavailable snapshot is presented as unknown', () {
    final store = RuntimeStore(initial: snapshot(8, 200, RuntimePhase.connected));
    store.markUnknown();
    expect(store.state.generation, 8);
    expect(store.state.monotonicMs, 200);
    expect(store.state.phase, RuntimePhase.unknown);
    expect(store.apply(snapshot(8, 201, RuntimePhase.reconnecting)), isTrue);
    expect(store.state.phase, RuntimePhase.reconnecting);
  });

  test('ordered unknown rejects stale payload and advances generation watermark', () {
    final store = RuntimeStore(initial: snapshot(8, 200, RuntimePhase.connected));
    expect(store.applyUnknown(generation: 7, monotonicMs: 300), isFalse);
    expect(store.state.phase, RuntimePhase.connected);

    expect(store.applyUnknown(generation: 9, monotonicMs: 1), isTrue);
    expect(store.state.generation, 9);
    expect(store.state.phase, RuntimePhase.unknown);
    expect(store.apply(snapshot(8, 400, RuntimePhase.connected)), isFalse);
  });
}
