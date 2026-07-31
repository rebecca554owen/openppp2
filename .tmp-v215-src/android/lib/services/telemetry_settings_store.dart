import 'dart:async';
import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import '../models/telemetry_settings.dart';

class TelemetrySettingsStore {
  static const _key = 'openppp2_telemetry_settings_v1';

  static final TelemetrySettingsStore _instance = TelemetrySettingsStore._();
  factory TelemetrySettingsStore() => _instance;
  TelemetrySettingsStore._();

  final _changes = StreamController<void>.broadcast();
  Stream<void> get changes => _changes.stream;

  Future<TelemetrySettings> settings() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_key);
    if (raw == null || raw.isEmpty) {
      return const TelemetrySettings();
    }
    try {
      final decoded = jsonDecode(raw);
      if (decoded is Map) {
        return TelemetrySettings.fromMap(Map<String, dynamic>.from(decoded));
      }
    } catch (_) {}
    return const TelemetrySettings();
  }

  Future<void> save(TelemetrySettings settings) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_key, jsonEncode(settings.toMap()));
    _changes.add(null);
  }
}
