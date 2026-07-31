import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Global, app-wide theme mode controller.
///
/// Backed by SharedPreferences key `theme_mode` with values:
///   - "system" (default)
///   - "light"
///   - "dark"
class ThemeController {
  static const _prefsKey = 'theme_mode';

  ThemeController._();
  static final ThemeController instance = ThemeController._();

  final ValueNotifier<ThemeMode> mode = ValueNotifier<ThemeMode>(ThemeMode.system);

  bool _loaded = false;

  Future<void> load() async {
    if (_loaded) return;
    final prefs = await SharedPreferences.getInstance();
    mode.value = _decode(prefs.getString(_prefsKey));
    _loaded = true;
  }

  Future<void> set(ThemeMode m) async {
    mode.value = m;
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_prefsKey, _encode(m));
  }

  static ThemeMode _decode(String? s) {
    switch (s) {
      case 'light':
        return ThemeMode.light;
      case 'dark':
        return ThemeMode.dark;
      default:
        return ThemeMode.system;
    }
  }

  static String _encode(ThemeMode m) {
    switch (m) {
      case ThemeMode.light:
        return 'light';
      case ThemeMode.dark:
        return 'dark';
      case ThemeMode.system:
        return 'system';
    }
  }
}
