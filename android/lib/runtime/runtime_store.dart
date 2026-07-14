import 'package:flutter/foundation.dart';

import 'runtime_snapshot.dart';

class RuntimeStore extends ChangeNotifier {
  RuntimeStore({RuntimeSnapshot? initial})
      : _state = initial ??
            const RuntimeSnapshot(
              generation: 0,
              monotonicMs: 0,
              phase: RuntimePhase.idle,
            );

  RuntimeSnapshot _state;
  RuntimeSnapshot get state => _state;

  bool apply(RuntimeSnapshot incoming) {
    if (incoming.generation < _state.generation) {
      return false;
    }
    if (incoming.generation == _state.generation &&
        incoming.monotonicMs <= _state.monotonicMs) {
      return false;
    }
    _state = incoming;
    notifyListeners();
    return true;
  }

  bool markUnknown() {
    if (_state.phase == RuntimePhase.unknown) return false;
    _state = RuntimeSnapshot(
      generation: _state.generation,
      monotonicMs: _state.monotonicMs,
      phase: RuntimePhase.unknown,
      role: _state.role,
      server: _state.server,
      transport: _state.transport,
      requestedMuxMode: _state.requestedMuxMode,
      effectiveMuxMode: _state.effectiveMuxMode,
      muxFallbackReason: _state.muxFallbackReason,
      p2pState: _state.p2pState,
      effectivePath: _state.effectivePath,
      lastError: _state.lastError,
    );
    notifyListeners();
    return true;
  }

  bool applyUnknown({required int generation, required int monotonicMs}) {
    if (generation < _state.generation ||
        (generation == _state.generation && monotonicMs <= _state.monotonicMs)) {
      return false;
    }
    _state = RuntimeSnapshot(
      generation: generation,
      monotonicMs: monotonicMs,
      phase: RuntimePhase.unknown,
    );
    notifyListeners();
    return true;
  }
}
