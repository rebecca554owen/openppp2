import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../vpn_service.dart';
import '../widgets/debug_panel.dart';
import 'settings_page.dart';

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> with WidgetsBindingObserver {
  final _vpnService = VpnService();
  VpnState _state = VpnState.disconnected;
  VpnStatistics _stats = const VpnStatistics();
  DateTime? _connectedAt;
  Timer? _durationTimer;
  Timer? _connectWatchdogTimer;
  Timer? _statePollTimer;
  Timer? _statsPollTimer;
  Timer? _logPollTimer;
  String _duration = '00:00:00';
  String? _lastError;
  bool _debugPanelEnabled = false;
  String _debugLog = '';
  String _logPath = '';

  StreamSubscription<VpnState>? _stateSub;
  StreamSubscription<VpnStatistics>? _statsSub;
  StreamSubscription<String>? _errorSub;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _vpnService.init();
    _stateSub = _vpnService.stateStream.listen((state) {
      _applyState(state);
    });
    _statsSub = _vpnService.statsStream.listen((stats) {
      _connectWatchdogTimer?.cancel();
      setState(() {
        _stats = stats;
        if (_state == VpnState.connecting) {
          _state = VpnState.connected;
          _connectedAt ??= DateTime.now();
          _startDurationTimer();
        }
      });
    });
    _errorSub = _vpnService.errorStream.listen((error) {
      if (!mounted) return;
      _connectWatchdogTimer?.cancel();
      setState(() => _lastError = error);
      unawaited(_showErrorDialog(error));
    });
    unawaited(_refreshStartupState());
    unawaited(_loadDebugPanelEnabled());
    _statePollTimer = Timer.periodic(const Duration(seconds: 2), (_) {
      if (_state == VpnState.connecting || _state == VpnState.connected) {
        unawaited(_vpnService.getState());
      }
    });
    _statsPollTimer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (_state == VpnState.connected || _state == VpnState.connecting) {
        unawaited(_refreshStatistics());
      }
    });
  }

  Future<void> _loadDebugPanelEnabled() async {
    final enabled = await SettingsPage.getDebugPanelEnabled();
    if (!mounted) return;
    setState(() => _debugPanelEnabled = enabled);
    if (enabled) {
      _startLogPolling();
      unawaited(_refreshDebugInfo());
    } else {
      _logPollTimer?.cancel();
      _logPollTimer = null;
    }
  }

  void _startLogPolling() {
    _logPollTimer?.cancel();
    _logPollTimer = Timer.periodic(const Duration(seconds: 2), (_) {
      unawaited(_refreshDebugInfo());
    });
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      unawaited(_refreshStartupState());
    }
  }

  void _startDurationTimer() {
    _durationTimer?.cancel();
    _durationTimer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (_connectedAt != null) {
        final diff = DateTime.now().difference(_connectedAt!);
        setState(() {
          _duration = _formatDuration(diff);
        });
      }
    });
  }

  Future<void> _refreshStartupState() async {
    final state = await _vpnService.getState();
    if (!mounted) return;
    _applyState(state);
    if (state == VpnState.connected || state == VpnState.connecting) {
      unawaited(_refreshStatistics());
    }
  }

  Future<void> _refreshStatistics() async {
    final stats = await _vpnService.getStatistics();
    if (!mounted) return;
    setState(() => _stats = stats);
  }

  void _applyState(VpnState state) {
    if (!mounted) return;
    setState(() {
      _state = state;
      if (state == VpnState.connected) {
        _connectedAt ??= DateTime.now();
        _connectWatchdogTimer?.cancel();
        _startDurationTimer();
      } else if (state == VpnState.disconnected) {
        _connectedAt = null;
        _connectWatchdogTimer?.cancel();
        _durationTimer?.cancel();
        _duration = '00:00:00';
        _stats = const VpnStatistics();
      }
    });
  }

  String _formatDuration(Duration d) {
    final hours = d.inHours.toString().padLeft(2, '0');
    final minutes = (d.inMinutes % 60).toString().padLeft(2, '0');
    final seconds = (d.inSeconds % 60).toString().padLeft(2, '0');
    return '$hours:$minutes:$seconds';
  }

  String _formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  }

  String _formatSpeed(int bytesPerSecond) {
    return '${_formatBytes(bytesPerSecond)}/s';
  }

  Future<void> _toggleConnection() async {
    if (_state == VpnState.disconnecting) {
      return;
    }

    if (_state == VpnState.connected || _state == VpnState.connecting) {
      await _stopVpnForDebug();
    } else {
      final config = await SettingsPage.getConfig();
      if (config == null || config.isEmpty) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('请先在设置中配置服务器信息')),
          );
          _openSettings();
        }
        return;
      }
      try {
        await _vpnService.clearLog();
        final vpnOptions = await SettingsPage.getVpnOptions();
        await _vpnService.connect(config, vpnOptions: vpnOptions);
        _startConnectWatchdog();
      } catch (e) {
        if (mounted) {
          final error = e.toString();
          setState(() => _lastError = error);
          await _showErrorDialog(error);
        }
      }
    }
  }

  Future<void> _showErrorDialog(String error) async {
    if (!mounted) return;
    final log = await _vpnService.readLog();
    final logPath = await _vpnService.getLogPath();
    final details = [
      '错误:',
      error,
      '',
      '日志文件:',
      logPath,
      '',
      '日志内容:',
      log.isEmpty ? '(暂无日志)' : log,
    ].join('\n');
    if (!mounted) return;
    await showDialog<void>(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: const Text('连接失败'),
          content: SizedBox(
            width: double.maxFinite,
            child: SingleChildScrollView(
              child: SelectableText(details),
            ),
          ),
          actions: [
            TextButton(
              onPressed: () async {
                await Clipboard.setData(ClipboardData(text: details));
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('错误信息已复制')),
                  );
                }
              },
              child: const Text('复制错误'),
            ),
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('关闭'),
            ),
          ],
        );
      },
    );
  }

  void _startConnectWatchdog() {
    _connectWatchdogTimer?.cancel();
    _connectWatchdogTimer = Timer(const Duration(seconds: 30), () async {
      if (!mounted || _state != VpnState.connecting) return;
      final log = await _vpnService.readLog();
      if (log.contains('onStarted key=') ||
          log.contains('VPN started with key=') ||
          log.contains('statistics=')) {
        if (!mounted) return;
        _applyState(VpnState.connected);
        return;
      }
      final hasRunCalled = log.contains('vpnThread started');
      final error = log.trim().isEmpty
          ? '连接超时（30秒）：VPN Service 没有返回状态，也没有生成日志。'
          : hasRunCalled
              ? '连接超时（30秒）：native 引擎已启动但未完成握手。\n可能原因：\n• 服务器地址或端口不可达\n• 密钥/算法配置不匹配\n• 网络阻断（DNS/防火墙）\n请检查设置中的 OpenPPP2 JSON 配置。'
              : '连接超时（30秒）：VPN 未进入已连接状态。';
      if (!mounted || _state != VpnState.connecting) return;
      setState(() {
        _state = VpnState.disconnected;
        _lastError = error;
      });
      await _showErrorDialog(error);
    });
  }

  Future<void> _refreshDebugInfo() async {
    final log = await _vpnService.readLog();
    final path = await _vpnService.getLogPath();
    if (!mounted) return;
    setState(() {
      _debugLog = log;
      _logPath = path;
    });
  }

  Future<void> _copyDebugInfo() async {
    final text = [
      'OpenPPP2 调试信息',
      '状态: ${_getStateText()}',
      '日志文件: $_logPath',
      '',
      _debugLog.isEmpty ? '(暂无日志)' : _debugLog,
    ].join('\n');
    await Clipboard.setData(ClipboardData(text: text));
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('调试信息已复制')),
    );
  }

  Future<void> _clearDebugLog() async {
    await _vpnService.clearLog();
    await _refreshDebugInfo();
  }

  Future<void> _stopVpnForDebug() async {
    _connectWatchdogTimer?.cancel();
    await _vpnService.disconnect();
    if (!mounted) return;
    setState(() => _state = VpnState.disconnected);
  }

  void _openSettings() {
    Navigator.of(context).push(
      MaterialPageRoute(builder: (_) => const SettingsPage()),
    ).then((_) {
      if (mounted) {
        unawaited(_loadDebugPanelEnabled());
      }
    });
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _stateSub?.cancel();
    _statsSub?.cancel();
    _errorSub?.cancel();
    _connectWatchdogTimer?.cancel();
    _statePollTimer?.cancel();
    _statsPollTimer?.cancel();
    _logPollTimer?.cancel();
    _durationTimer?.cancel();
    super.dispose();
  }

  Color _getStateColor() {
    switch (_state) {
      case VpnState.connected:
        return Colors.green;
      case VpnState.connecting:
      case VpnState.disconnecting:
        return Colors.orange;
      case VpnState.disconnected:
        return Colors.grey;
    }
  }

  String _getStateText() {
    switch (_state) {
      case VpnState.connected:
        return '已连接';
      case VpnState.connecting:
        return '连接中...';
      case VpnState.disconnecting:
        return '断开中...';
      case VpnState.disconnected:
        return '未连接';
    }
  }

  IconData _getButtonIcon() {
    switch (_state) {
      case VpnState.connected:
        return Icons.stop_circle_outlined;
      case VpnState.connecting:
      case VpnState.disconnecting:
        return Icons.hourglass_top;
      case VpnState.disconnected:
        return Icons.power_settings_new;
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isActive = _state == VpnState.connected;
    final isBusy =
        _state == VpnState.connecting || _state == VpnState.disconnecting;

    return Scaffold(
      appBar: AppBar(
        title: const Text('OpenPPP2'),
        centerTitle: true,
        actions: [
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: _openSettings,
          ),
        ],
      ),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            _StatusHeader(
              color: _getStateColor(),
              text: _getStateText(),
              duration: isActive ? _duration : null,
            ),
            const SizedBox(height: 20),
            Center(
              child: GestureDetector(
                onTap: _state == VpnState.disconnecting ? null : _toggleConnection,
                child: Container(
                  width: 132,
                  height: 132,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: isActive
                        ? theme.colorScheme.error.withValues(alpha: 0.1)
                        : theme.colorScheme.primary.withValues(alpha: 0.1),
                    border: Border.all(
                      color: isActive
                          ? theme.colorScheme.error
                          : theme.colorScheme.primary,
                      width: 3,
                    ),
                  ),
                  child: isBusy
                      ? Center(
                          child: SizedBox(
                            width: 44,
                            height: 44,
                            child: CircularProgressIndicator(
                              color: theme.colorScheme.primary,
                              strokeWidth: 3,
                            ),
                          ),
                        )
                      : Icon(
                          _getButtonIcon(),
                          size: 56,
                          color: isActive
                              ? theme.colorScheme.error
                              : theme.colorScheme.primary,
                        ),
                ),
              ),
            ),
            const SizedBox(height: 8),
            Center(
              child: Text(
                isActive
                    ? '点击断开'
                    : _state == VpnState.connecting
                        ? '点击强制停止'
                        : '点击连接',
                style: theme.textTheme.bodyMedium?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
            ),
            if (isActive)
              Row(
                children: [
                  Expanded(
                    child: _StatCard(
                      icon: Icons.arrow_upward,
                      label: '上行速度',
                      value: _formatSpeed(_stats.txSpeedBytes),
                      subtitle: '总上行 ${_formatBytes(_stats.outBytes)}',
                      color: Colors.orange,
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: _StatCard(
                      icon: Icons.arrow_downward,
                      label: '下行速度',
                      value: _formatSpeed(_stats.rxSpeedBytes),
                      subtitle: '总下行 ${_formatBytes(_stats.inBytes)}',
                      color: Colors.blue,
                    ),
                  ),
                ],
              ),
            if (_lastError != null) ...[
              const SizedBox(height: 12),
              Card(
                color: theme.colorScheme.errorContainer,
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Text(
                    _lastError!,
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: theme.colorScheme.onErrorContainer,
                    ),
                  ),
                ),
              ),
            ],
            if (_debugPanelEnabled) ...[
              const SizedBox(height: 16),
              DebugPanel(
                stateText: _getStateText(),
                logPath: _logPath,
                logText: _debugLog,
                onRefresh: _refreshDebugInfo,
                onCopy: _copyDebugInfo,
                onClear: _clearDebugLog,
                onStop: _stopVpnForDebug,
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _StatCard extends StatelessWidget {
  final IconData icon;
  final String label;
  final String value;
  final String? subtitle;
  final Color color;

  const _StatCard({
    required this.icon,
    required this.label,
    required this.value,
    this.subtitle,
    required this.color,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            Icon(icon, color: color, size: 24),
            const SizedBox(height: 4),
            Text(label, style: theme.textTheme.bodySmall),
            const SizedBox(height: 4),
            Text(
              value,
              style: theme.textTheme.titleMedium?.copyWith(
                fontWeight: FontWeight.bold,
                fontFeatures: [const FontFeature.tabularFigures()],
              ),
            ),
            if (subtitle != null) ...[
              const SizedBox(height: 2),
              Text(
                subtitle!,
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                  fontFeatures: [const FontFeature.tabularFigures()],
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _StatusHeader extends StatelessWidget {
  final Color color;
  final String text;
  final String? duration;

  const _StatusHeader({
    required this.color,
    required this.text,
    required this.duration,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Row(
          children: [
            Container(
              width: 12,
              height: 12,
              decoration: BoxDecoration(color: color, shape: BoxShape.circle),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                text,
                style: theme.textTheme.titleMedium?.copyWith(
                  color: color,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ),
            if (duration != null)
              Text(
                duration!,
                style: theme.textTheme.bodyMedium,
              ),
          ],
        ),
      ),
    );
  }
}

