import 'package:flutter/material.dart';
import 'app_shell.dart';
import 'services/theme_controller.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await ThemeController.instance.load();
  runApp(const OpenPPP2App());
}

class OpenPPP2App extends StatelessWidget {
  const OpenPPP2App({super.key});

  static const _seed = Color(0xFF2563EB); // brand blue

  ThemeData _light() => ThemeData(
        colorSchemeSeed: _seed,
        useMaterial3: true,
        brightness: Brightness.light,
        scaffoldBackgroundColor: const Color(0xFFF7F7FB),
      );

  ThemeData _dark() {
    final base = ColorScheme.fromSeed(
      seedColor: _seed,
      brightness: Brightness.dark,
    );
    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.dark,
      colorScheme: base,
      // Slightly deeper than the default M3 dark surface so cards (which use
      // the lighter surfaceContainer tones) stand out clearly on the page.
      scaffoldBackgroundColor: const Color(0xFF0E1116),
      cardTheme: CardThemeData(
        color: base.surfaceContainerHigh,
        elevation: 0,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
      ),
      appBarTheme: AppBarTheme(
        backgroundColor: const Color(0xFF0E1116),
        foregroundColor: base.onSurface,
        elevation: 0,
        scrolledUnderElevation: 0,
      ),
      navigationBarTheme: NavigationBarThemeData(
        backgroundColor: const Color(0xFF14181F),
        indicatorColor: base.primary.withValues(alpha: 0.20),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return ValueListenableBuilder<ThemeMode>(
      valueListenable: ThemeController.instance.mode,
      builder: (context, mode, _) {
        return MaterialApp(
          title: 'OPENPPP2',
          debugShowCheckedModeBanner: false,
          theme: _light(),
          darkTheme: _dark(),
          themeMode: mode,
          home: const AppShell(),
        );
      },
    );
  }
}
