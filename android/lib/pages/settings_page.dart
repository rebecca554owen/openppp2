import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../services/profile_store.dart';
import '../services/theme_controller.dart';
import '../vpn_service.dart';
import '../widgets/debug_panel.dart';

class SettingsPage extends StatefulWidget {
  const SettingsPage({super.key});

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  final _store = ProfileStore();
  final _vpnService = VpnService();

  bool _debugPanelEnabled = false;
  bool _loading = true;
  VpnState _state = VpnState.disconnected;
  String _debugLog = '';
  String _logPath = '';
  Timer? _pollTimer;
  StreamSubscription<VpnState>? _stateSub;

  @override
  void initState() {
    super.initState();
    _vpnService.init();
    _stateSub = _vpnService.stateStream.listen((s) {
      if (!mounted) return;
      setState(() => _state = s);
    });
    _load();
  }

  Future<void> _load() async {
    final enabled = await _store.getDebugPanelEnabled();
    if (!mounted) return;
    setState(() {
      _debugPanelEnabled = enabled;
      _loading = false;
    });
    if (enabled) {
      _startPoll();
      unawaited(_refresh());
    }
  }

  void _startPoll() {
    _pollTimer?.cancel();
    _pollTimer = Timer.periodic(const Duration(seconds: 2), (_) {
      unawaited(_refresh());
    });
  }

  Future<void> _refresh() async {
    final state = await _vpnService.getState();
    final log = await _vpnService.readLog();
    final path = await _vpnService.getLogPath();
    if (!mounted) return;
    setState(() {
      _state = state;
      _debugLog = log;
      _logPath = path;
    });
  }

  Future<void> _setDebugPanel(bool v) async {
    setState(() => _debugPanelEnabled = v);
    await _store.setDebugPanelEnabled(v);
    if (v) {
      _startPoll();
      unawaited(_refresh());
    } else {
      _pollTimer?.cancel();
      _pollTimer = null;
    }
  }

  Future<void> _copyLog() async {
    await Clipboard.setData(ClipboardData(
      text: _debugLog.isEmpty ? '(暂无日志)' : _debugLog,
    ));
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('日志已复制')),
    );
  }

  Future<void> _clearLog() async {
    await _vpnService.clearLog();
    await _refresh();
  }

  Future<void> _stopVpn() async {
    await _vpnService.disconnect();
    await _refresh();
  }

  String _stateText() {
    switch (_state) {
      case VpnState.connected:
        return '已连接';
      case VpnState.connecting:
        return '连接中';
      case VpnState.disconnecting:
        return '断开中';
      case VpnState.disconnected:
        return '未连接';
    }
  }

  @override
  void dispose() {
    _pollTimer?.cancel();
    _stateSub?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      appBar: AppBar(
        title: const Text('设置'),
        centerTitle: true,
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              padding: const EdgeInsets.all(16),
              children: [
                Card(
                  child: Column(
                    children: [
                      ListTile(
                        leading: const Icon(Icons.info_outline_rounded),
                        title: const Text('OPENPPP2'),
                        subtitle: const Text('Android Client · v1.0.0'),
                      ),
                      const Divider(height: 0),
                      _ThemeModeTile(),
                      const Divider(height: 0),
                      SwitchListTile(
                        secondary: const Icon(Icons.bug_report_outlined),
                        value: _debugPanelEnabled,
                        title: const Text('显示调试面板'),
                        subtitle: const Text('在主页和此页显示日志/状态/停止按钮'),
                        onChanged: _setDebugPanel,
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 12),
                if (_debugPanelEnabled)
                  DebugPanel(
                    stateText: _stateText(),
                    logPath: _logPath,
                    logText: _debugLog,
                    onRefresh: _refresh,
                    onCopy: _copyLog,
                    onClear: _clearLog,
                    onStop: _stopVpn,
                  ),
                const SizedBox(height: 16),
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 4),
                  child: Text(
                    '配置文件请在「配置文件」页面中编辑，启动参数请在「启动参数」页面中编辑。',
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                  ),
                ),
              ],
            ),
    );
  }
}

class _ThemeModeTile extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return ValueListenableBuilder<ThemeMode>(
      valueListenable: ThemeController.instance.mode,
      builder: (context, mode, _) {
        return ListTile(
          leading: Icon(_iconFor(mode)),
          title: const Text('主题'),
          subtitle: Text(_labelFor(mode)),
          trailing: SegmentedButton<ThemeMode>(
            showSelectedIcon: false,
            style: const ButtonStyle(
              visualDensity: VisualDensity.compact,
              tapTargetSize: MaterialTapTargetSize.shrinkWrap,
            ),
            segments: const [
              ButtonSegment(
                value: ThemeMode.system,
                icon: Icon(Icons.brightness_auto_rounded, size: 18),
                tooltip: '跟随系统',
              ),
              ButtonSegment(
                value: ThemeMode.light,
                icon: Icon(Icons.light_mode_rounded, size: 18),
                tooltip: '浅色',
              ),
              ButtonSegment(
                value: ThemeMode.dark,
                icon: Icon(Icons.dark_mode_rounded, size: 18),
                tooltip: '深色',
              ),
            ],
            selected: {mode},
            onSelectionChanged: (s) {
              if (s.isNotEmpty) ThemeController.instance.set(s.first);
            },
          ),
        );
      },
    );
  }

  IconData _iconFor(ThemeMode m) {
    switch (m) {
      case ThemeMode.light:
        return Icons.light_mode_rounded;
      case ThemeMode.dark:
        return Icons.dark_mode_rounded;
      case ThemeMode.system:
        return Icons.brightness_auto_rounded;
    }
  }

  String _labelFor(ThemeMode m) {
    switch (m) {
      case ThemeMode.light:
        return '浅色模式';
      case ThemeMode.dark:
        return '深色模式';
      case ThemeMode.system:
        return '跟随系统';
    }
  }
}
