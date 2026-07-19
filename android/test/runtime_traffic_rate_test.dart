import 'package:flutter_test/flutter_test.dart';
import 'package:openppp2_mobile/runtime/runtime_snapshot.dart';
import 'package:openppp2_mobile/runtime/runtime_traffic_rate.dart';

RuntimeSnapshot sample({
  int generation = 1,
  required int monotonicMs,
  int rxBytes = 0,
  int txBytes = 0,
  int connectedMonotonicMs = 0,
  RuntimePhase phase = RuntimePhase.connected,
}) {
  return RuntimeSnapshot(
    generation: generation,
    monotonicMs: monotonicMs,
    phase: phase,
    traffic: RuntimeTrafficSnapshot(rxBytes: rxBytes, txBytes: txBytes),
    connectedMonotonicMs: connectedMonotonicMs,
  );
}

void main() {
  group('traffic rate', () {
    test('derives a rate from the snapshot clock, not the sampling interval', () {
      final previous = sample(monotonicMs: 1000, rxBytes: 1000, txBytes: 500);
      // Two seconds of snapshot time, whatever the UI poll interval was.
      final current = sample(monotonicMs: 3000, rxBytes: 5000, txBytes: 1500);

      final rate = RuntimeTrafficRate.between(previous, current);
      expect(rate.rxBytes, 5000);
      expect(rate.txBytes, 1500);
      expect(rate.rxBytesPerSecond, 2000);
      expect(rate.txBytesPerSecond, 500);
    });

    test('the first sample reports totals with no rate', () {
      final rate = RuntimeTrafficRate.between(
        null,
        sample(monotonicMs: 1000, rxBytes: 4096, txBytes: 2048),
      );
      expect(rate.rxBytes, 4096);
      expect(rate.txBytes, 2048);
      expect(rate.rxBytesPerSecond, 0);
      expect(rate.txBytesPerSecond, 0);
    });

    test('a new generation does not report a spike across sessions', () {
      final previous =
          sample(generation: 1, monotonicMs: 9000, rxBytes: 10000000);
      final current = sample(generation: 2, monotonicMs: 100, rxBytes: 512);

      final rate = RuntimeTrafficRate.between(previous, current);
      expect(rate.rxBytes, 512);
      expect(rate.rxBytesPerSecond, 0);
    });

    test('counters that moved backwards report no rate', () {
      final previous = sample(monotonicMs: 1000, rxBytes: 8000, txBytes: 8000);
      final current = sample(monotonicMs: 2000, rxBytes: 10, txBytes: 10);

      final rate = RuntimeTrafficRate.between(previous, current);
      expect(rate.rxBytesPerSecond, 0);
      expect(rate.txBytesPerSecond, 0);
    });

    test('a clock that did not advance reports no rate', () {
      final previous = sample(monotonicMs: 2000, rxBytes: 100);
      final current = sample(monotonicMs: 2000, rxBytes: 900);

      expect(RuntimeTrafficRate.between(previous, current).rxBytesPerSecond, 0);
    });
  });

  group('connected elapsed time', () {
    test('is measured against the snapshot clock', () {
      final snapshot =
          sample(monotonicMs: 42000, connectedMonotonicMs: 30000);
      expect(connectedElapsedMs(snapshot), 12000);
    });

    test('is zero while not connected', () {
      expect(
        connectedElapsedMs(
          sample(monotonicMs: 42000, phase: RuntimePhase.connecting),
        ),
        0,
      );
    });

    test('is zero when the clock is behind the connect stamp', () {
      final snapshot =
          sample(monotonicMs: 1000, connectedMonotonicMs: 30000);
      expect(connectedElapsedMs(snapshot), 0);
    });
  });
}
