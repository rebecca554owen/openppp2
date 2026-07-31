import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Device identity sourced from native Kotlin (same logic as iOS / VPN process).
class TelemetryIdentity {
  TelemetryIdentity._();

  static const _channel = MethodChannel('supersocksr.ppp/vpn');

  static String? _cachedMachineId;
  static Map<String, String>? _cachedAttributes;

  static Future<String> machineId() async {
    if (_cachedMachineId != null && _cachedMachineId!.isNotEmpty) {
      return _cachedMachineId!;
    }
    final payload = await _loadPayload();
    _cachedMachineId = (payload['machineId'] ?? '').toString();
    return _cachedMachineId!;
  }

  static Future<Map<String, String>> resourceAttributes() async {
    if (_cachedAttributes != null) return _cachedAttributes!;
    final payload = await _loadPayload();
    final raw = payload['resourceAttributes'];
    if (raw is Map) {
      _cachedAttributes = raw.map(
        (key, value) => MapEntry(key.toString(), value.toString()),
      );
    } else {
      _cachedAttributes = const {};
    }
    return _cachedAttributes!;
  }

  static Future<void> installIfNeeded() async {
    await machineId();
  }

  @visibleForTesting
  static void clearCacheForTest() {
    _cachedMachineId = null;
    _cachedAttributes = null;
  }

  static Future<Map<String, dynamic>> _loadPayload() async {
    try {
      final result = await _channel.invokeMethod<Object?>('getTelemetryIdentity');
      if (result is Map) {
        return Map<String, dynamic>.from(result);
      }
    } catch (_) {}
    return const {};
  }
}
