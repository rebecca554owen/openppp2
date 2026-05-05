import 'dart:async';
import 'dart:convert';
import 'package:flutter/services.dart';

enum VpnState {
  disconnected,
  connecting,
  connected,
  disconnecting,
}

class VpnStatistics {
  final int txSpeedBytes;
  final int rxSpeedBytes;
  final int inBytes;
  final int outBytes;

  const VpnStatistics({
    this.txSpeedBytes = 0,
    this.rxSpeedBytes = 0,
    this.inBytes = 0,
    this.outBytes = 0,
  });

  factory VpnStatistics.fromJson(
    Map<String, dynamic> json, {
    VpnStatistics? previous,
  }) {
    int? value(List<String> keys) {
      for (final key in keys) {
        final raw = json[key];
        if (raw != null) {
          return int.tryParse(raw.toString());
        }
      }
      return null;
    }

    final nativeTxSpeedBytes = value(['tx', 'txBytes', 'outgoing', 'outgoingTraffic']) ?? 0;
    final nativeRxSpeedBytes = value(['rx', 'rxBytes', 'incoming', 'incomingTraffic']) ?? 0;
    final nativeInBytes = value(['in', 'inBytes', 'incomingTotal', 'incomingTrafficTotal']);
    final nativeOutBytes = value(['out', 'outBytes', 'outgoingTotal', 'outgoingTrafficTotal']);
    final previousInBytes = previous?.inBytes ?? 0;
    final previousOutBytes = previous?.outBytes ?? 0;
    final hasPreviousTotals = previousInBytes > 0 || previousOutBytes > 0;
    final inBytes = nativeInBytes == null
        ? previousInBytes + nativeRxSpeedBytes
        : nativeInBytes < previousInBytes
            ? previousInBytes
            : nativeInBytes;
    final outBytes = nativeOutBytes == null
        ? previousOutBytes + nativeTxSpeedBytes
        : nativeOutBytes < previousOutBytes
            ? previousOutBytes
            : nativeOutBytes;
    final rxSpeedBytes = nativeInBytes != null && hasPreviousTotals
        ? inBytes - previousInBytes
        : nativeRxSpeedBytes;
    final txSpeedBytes = nativeOutBytes != null && hasPreviousTotals
        ? outBytes - previousOutBytes
        : nativeTxSpeedBytes;

    return VpnStatistics(
      txSpeedBytes: txSpeedBytes,
      rxSpeedBytes: rxSpeedBytes,
      inBytes: inBytes,
      outBytes: outBytes,
    );
  }
}

class VpnService {
  static const _channel = MethodChannel('supersocksr.ppp/vpn');
  static const _eventChannel = EventChannel('supersocksr.ppp/vpn_events');

  static final VpnService _instance = VpnService._internal();
  factory VpnService() => _instance;
  VpnService._internal();

  final _stateController = StreamController<VpnState>.broadcast();
  final _statsController = StreamController<VpnStatistics>.broadcast();
  final _errorController = StreamController<String>.broadcast();

  Stream<VpnState> get stateStream => _stateController.stream;
  Stream<VpnStatistics> get statsStream => _statsController.stream;
  Stream<String> get errorStream => _errorController.stream;

  VpnState _currentState = VpnState.disconnected;
  VpnState get currentState => _currentState;

  VpnStatistics _currentStats = const VpnStatistics();
  VpnStatistics get currentStats => _currentStats;
  String? _lastStatsRaw;

  bool _initialized = false;
  StreamSubscription<dynamic>? _eventSubscription;

  void init() {
    if (_initialized) return;
    _initialized = true;
    _channel.setMethodCallHandler(_handleMethodCall);
    _eventSubscription = _eventChannel.receiveBroadcastStream().listen(_handleEvent);
  }

  Future<void> _handleMethodCall(MethodCall call) async {
    switch (call.method) {
      case 'onStateChanged':
        final stateIndex = call.arguments as int;
        _updateState(_stateFromIndex(stateIndex));
        break;
      case 'onStatistics':
        _applyStatistics(call.arguments as String);
        break;
    }
  }

  void _handleEvent(dynamic event) {
    if (event is Map) {
      final type = event['type'] as String?;
      if (type == 'state') {
        final stateIndex = event['value'] as int;
        _updateState(_stateFromIndex(stateIndex));
      } else if (type == 'statistics') {
        final value = event['value'];
        _applyStatistics(
          value is String ? value : jsonEncode(Map<String, dynamic>.from(value as Map)),
        );
      } else if (type == 'error') {
        final value = event['value']?.toString() ?? 'Unknown VPN error';
        _errorController.add(value);
        _updateState(VpnState.disconnected);
      }
    }
  }

  void _updateState(VpnState state) {
    if (_currentState == state) return;
    _currentState = state;
    if (state == VpnState.disconnected) {
      _resetStats();
    }
    _stateController.add(state);
  }

  void _resetStats() {
    _currentStats = const VpnStatistics();
    _lastStatsRaw = null;
    _statsController.add(_currentStats);
  }

  VpnStatistics _applyStatistics(String raw) {
    final normalizedRaw = raw.trim();
    if (normalizedRaw.isEmpty || normalizedRaw == '{}' || normalizedRaw == _lastStatsRaw) {
      return _currentStats;
    }
    final json = jsonDecode(normalizedRaw) as Map<String, dynamic>;
    if (!json.containsKey('tx') &&
        !json.containsKey('rx') &&
        !json.containsKey('in') &&
        !json.containsKey('out')) {
      return _currentStats;
    }
    _lastStatsRaw = normalizedRaw;
    _currentStats = VpnStatistics.fromJson(json, previous: _currentStats);
    _statsController.add(_currentStats);
    return _currentStats;
  }

  VpnState _stateFromIndex(int index) {
    if (index < 0 || index >= VpnState.values.length) {
      return VpnState.disconnected;
    }
    return VpnState.values[index];
  }

  Future<VpnState> getState() async {
    final stateIndex = await _channel.invokeMethod<int>('getState') ?? 0;
    final state = _stateFromIndex(stateIndex);
    _updateState(state);
    return state;
  }

  Future<bool> connect(
    String jsonConfig, {
    Map<String, dynamic>? vpnOptions,
  }) async {
    try {
      _resetStats();
      _updateState(VpnState.connecting);
      final result = await _channel.invokeMethod<bool>('connect', {
        'configJson': jsonConfig,
        'vpnOptions': vpnOptions ?? <String, dynamic>{},
      });
      return result ?? false;
    } on PlatformException catch (e) {
      _updateState(VpnState.disconnected);
      final details = e.details?.toString();
      throw Exception(
        details == null || details.isEmpty
            ? 'VPN connect failed: ${e.message}'
            : 'VPN connect failed: ${e.message}\n$details',
      );
    }
  }

  Future<bool> disconnect() async {
    try {
      _updateState(VpnState.disconnecting);
      final result = await _channel.invokeMethod<bool>('disconnect');
      _resetStats();
      return result ?? false;
    } on PlatformException catch (e) {
      throw Exception('VPN disconnect failed: ${e.message}');
    }
  }

  Future<VpnStatistics> getStatistics() async {
    final value = await _channel.invokeMethod<String>('getStatistics') ?? '{}';
    return _applyStatistics(value);
  }

  Future<String> readLog() async {
    try {
      return await _channel.invokeMethod<String>('readLog') ?? '';
    } on PlatformException catch (e) {
      return 'readLog failed: ${e.message}';
    }
  }

  Future<String> getLogPath() async {
    try {
      return await _channel.invokeMethod<String>('getLogPath') ?? '';
    } on PlatformException catch (e) {
      return 'getLogPath failed: ${e.message}';
    }
  }

  Future<void> clearLog() async {
    try {
      await _channel.invokeMethod<bool>('clearLog');
    } on PlatformException {
      return;
    }
  }

  Future<bool> requestVpnPermission() async {
    try {
      final result = await _channel.invokeMethod<bool>('requestPermission');
      return result ?? false;
    } on PlatformException {
      return false;
    }
  }

  void dispose() {
    _eventSubscription?.cancel();
    _stateController.close();
    _statsController.close();
    _errorController.close();
  }
}
