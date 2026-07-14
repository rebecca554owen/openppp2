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
}
