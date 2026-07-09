import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../models/config_profile.dart';
import '../models/launch_route_mode.dart';
import '../services/profile_store.dart';
import '../services/telemetry_settings_store.dart';
import '../vpn_service.dart';
import '../widgets/debug_panel.dart';
import '../widgets/profile_ui.dart';
import 'profile_edit_page.dart';

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> with WidgetsBindingObserver {
  final _vpnService = VpnService();
  final _store = ProfileStore();

  VpnState _state = VpnState.disconnected;
  VpnStatistics _stats = const VpnStatistics();
  List<ConfigProfile> _profiles = const [];
  ConfigProfile? _active;
  Map<String, dynamic> _launchOptions = Map<String, dynamic>.from(
    ProfileStore.defaultOptions,
  );
  DateTime? _connectedAt;
  String _duration = '00:00:00';
  String? _lastError;
  bool _debugPanelEnabled = false;
  String _debugLog = '';
  String _logPath = '';
  int _linkState = 6;
  bool _connectInFlight = false;

  Timer? _durationTimer;
  Timer? _connectWatchdogTimer;
  Timer? _logPollTimer;

  StreamSubscription<VpnState>? _stateSub;
  StreamSubscription<VpnStatistics>? _statsSub;
  StreamSubscription<String>? _errorSub;
  StreamSubscription<int>? _linkStateSub;
  StreamSubscription<void>? _storeSub;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _vpnService.init();
    _stateSub = _vpnService.stateStream.listen(_applyState);
    _statsSub = _vpnService.statsStream.listen((stats) {
      if (!mounted) return;
      setState(() => _stats = stats);
    });
    _errorSub = _vpnService.errorStream.listen((error) {
      if (!mounted) return;
      _connectWatchdogTimer?.cancel();
      setState(() => _lastError = error);
      unawaited(_showErrorDialog(error));
    });
    _linkStateSub = _vpnService.linkStateStream.listen(_applyLinkState);
    _storeSub = _store.changes.listen((_) => _refreshStore());

    unawaited(_refreshStore());
    unawaited(_refreshStartupState());
    unawaited(_loadDebugPanelEnabled());
  }

  Future<void> _refreshStore() async {
    final profiles = await _store.getProfiles();
    final active = await _store.getActive();
    Map<String, dynamic> options = Map<String, dynamic>.from(
      ProfileStore.defaultOptions,
    );
    if (active != null) {
      options = await _store.getProfileOptions(active.id);
    }
    if (!mounted) return;
    setState(() {
      _profiles = profiles;
      _active = active;
      _launchOptions = options;
    });
  }

  void _applyLinkState(int ls) {
    if (!mounted) return;
    final wasEstablished = _linkState == 0;
    final promoteConnected = ls == 0 && _state != VpnState.connected;
    final demoteReconnecting = wasEstablished &&
        ls != 0 &&
        ls != 6 &&
        _state == VpnState.connected;
    if (ls == _linkState && !promoteConnected && !demoteReconnecting) return;

    setState(() => _linkState = ls);
    if (promoteConnected) {
      _connectWatchdogTimer?.cancel();
      _applyState(VpnState.connected);
    } else if (demoteReconnecting) {
      _applyState(VpnState.connecting);
      _connectedAt = null;
    }
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      unawaited(_refreshStartupState());
      unawaited(_refreshStore());
      unawaited(_loadDebugPanelEnabled());
    }
  }

  Future<void> _loadDebugPanelEnabled() async {
    final enabled = await _store.getDebugPanelEnabled();
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

  void _startDurationTimer() {
    _durationTimer?.cancel();
    _durationTimer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (_connectedAt != null && mounted) {
        final diff = DateTime.now().difference(_connectedAt!);
        setState(() => _duration = _formatDuration(diff));
      }
    });
  }

  Future<void> _refreshStartupState() async {
    final state = await _vpnService.getState();
    if (!mounted) return;
    _applyState(state);
    if (state == VpnState.connected || state == VpnState.connecting) {
      final linkState = await _vpnService.getLinkState();
      if (!mounted) return;
      _applyLinkState(linkState);
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
        _linkState = 6;
      }
    });
  }

  String _formatDuration(Duration d) {
    final h = d.inHours.toString().padLeft(2, '0');
    final m = (d.inMinutes % 60).toString().padLeft(2, '0');
    final s = (d.inSeconds % 60).toString().padLeft(2, '0');
    return '$h:$m:$s';
  }

  String _formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  }

  String _formatSpeed(int bps) => '${_formatBytes(bps)}/s';

  Future<void> _toggleConnection() async {
    if (_state == VpnState.disconnecting) return;

    if (_state == VpnState.connected || _state == VpnState.connecting) {
      await _stopVpnForDebug();
      return;
    }

    if (_connectInFlight) return;

    final profile = _active;
    if (profile == null || profile.json.trim().isEmpty) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('请先添加并选择一个配置')),
      );
      return;
    }
    _connectInFlight = true;
    try {
      await _vpnService.clearLog();
      final options = await _store.getProfileOptions(profile.id);
      final telemetry = await TelemetrySettingsStore().settings();
      final mergedJson = ProfileStore.effectiveJson(
        profile.json,
        options,
        telemetry: telemetry,
      );
      await _vpnService.connect(mergedJson, vpnOptions: options);
      _startConnectWatchdog();
    } catch (e) {
      if (!mounted) return;
      final error = e.toString();
      setState(() => _lastError = error);
      await _showErrorDialog(error);
    } finally {
      _connectInFlight = false;
    }
  }

  static const int _connectMaxSeconds = 180;

  void _startConnectWatchdog() {
    _connectWatchdogTimer?.cancel();
    final startedAt = DateTime.now();
    _connectWatchdogTimer =
        Timer.periodic(const Duration(seconds: 5), (timer) async {
      if (!mounted || _state != VpnState.connecting) {
        timer.cancel();
        return;
      }
      if (_vpnService.currentState == VpnState.connected) {
        timer.cancel();
        if (!mounted) return;
        _applyState(VpnState.connected);
        return;
      }
      // onStarted / VPN started means the native engine is live even when
      // linkState polling still reports CONNECTING.
      final log = await _vpnService.readLog();
      if (log.contains('onStarted key=') || log.contains('VPN started with key=')) {
        timer.cancel();
        if (!mounted) return;
        _applyState(VpnState.connected);
        return;
      }
      if (_linkState == 0) {
        timer.cancel();
        if (!mounted) return;
        _applyState(VpnState.connected);
        return;
      }
      final hbAgeMs = await _vpnService.getVpnHeartbeatAgeMs();
      final hbStale = hbAgeMs < 0 || hbAgeMs > 30000;
      final totalSec = DateTime.now().difference(startedAt).inSeconds;
      if (!hbStale && totalSec < _connectMaxSeconds) return;
      timer.cancel();
      final reason = totalSec >= _connectMaxSeconds
          ? '超过 ${_connectMaxSeconds}s 上限'
          : ':vpn 心跳已停 ${(hbAgeMs / 1000).toStringAsFixed(1)}s';
      final error = log.trim().isEmpty
          ? '连接超时（$reason）：VPN Service 没有返回状态，也没有生成日志。'
          : log.contains('vpnThread started')
              ? '连接超时（$reason）：native 引擎已启动但未完成握手。\n请检查所选配置的服务器地址、密钥与网络连通性。'
              : '连接超时（$reason）：VPN 未进入已连接状态。';
      if (!mounted || _state != VpnState.connecting) return;
      setState(() {
        _state = VpnState.disconnected;
        _lastError = error;
      });
      await _vpnService.disconnect();
      await _showErrorDialog(error);
    });
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
      builder: (ctx) => AlertDialog(
        title: const Text('连接失败'),
        content: SizedBox(
          width: double.maxFinite,
          child: SingleChildScrollView(child: SelectableText(details)),
        ),
        actions: [
          TextButton(
            onPressed: () async {
              await Clipboard.setData(ClipboardData(text: details));
              if (ctx.mounted) {
                ScaffoldMessenger.of(ctx).showSnackBar(
                  const SnackBar(content: Text('错误信息已复制')),
                );
              }
            },
            child: const Text('复制错误'),
          ),
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('关闭'),
          ),
        ],
      ),
    );
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

  Future<void> _applyProfile(ConfigProfile profile) async {
    if (profile.id == _active?.id) return;
    await _store.setActive(profile.id);
    await _refreshStore();
    if (!mounted) return;
    if (_state == VpnState.connected || _state == VpnState.connecting) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('已切换到「${profile.name}」，重连后生效')),
      );
    }
  }

  Future<void> _editProfile(ConfigProfile profile) async {
    final ok = await Navigator.of(context).push<bool>(
      MaterialPageRoute(builder: (_) => ProfileEditPage(profile: profile)),
    );
    if (ok == true) await _refreshStore();
  }

  Future<void> _addProfile() async {
    final ok = await Navigator.of(context).push<bool>(
      MaterialPageRoute(builder: (_) => const ProfileEditPage()),
    );
    if (ok == true) await _refreshStore();
  }

  Future<void> _togglePin(ConfigProfile profile) async {
    await _store.toggleFavorite(profile.id);
    await _refreshStore();
  }

  Future<void> _updateLaunchOption(
    void Function(Map<String, dynamic> options) mutate,
  ) async {
    final active = _active;
    if (active == null) return;
    await _store.updateProfileOptions(active.id, mutate);
    if (!mounted) return;
    final next = await _store.getProfileOptions(active.id);
    if (!mounted) return;
    setState(() => _launchOptions = next);
    if (_state == VpnState.connected || _state == VpnState.connecting) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('快捷设置已保存，重连后生效')),
      );
    }
  }

  String _connectingLabel() {
    if (!_debugPanelEnabled) return '连接中...';
    switch (_linkState) {
      case 4:
        return '重连中...';
      case 5:
        return '握手中...';
      case 2:
        return '初始化客户端...';
      case 3:
        return '初始化交换器...';
      case 6:
        return '启动引擎...';
      default:
        return '连接中...';
    }
  }

  String _getStateText() {
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

  bool get _isActive => _state == VpnState.connected;
  bool get _isBusy =>
      _state == VpnState.connecting || _state == VpnState.disconnecting;

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _stateSub?.cancel();
    _statsSub?.cancel();
    _errorSub?.cancel();
    _linkStateSub?.cancel();
    _storeSub?.cancel();
    _connectWatchdogTimer?.cancel();
    _logPollTimer?.cancel();
    _durationTimer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isActive = _isActive;
    final isBusy = _isBusy;
    final isVpnLive = isActive || isBusy;

    final statusTitle = isActive
        ? '已连接'
        : (_state == VpnState.connecting
            ? _connectingLabel()
            : (_state == VpnState.disconnecting ? '断开中...' : '未连接'));
    final statusDetail = isActive
        ? _duration
        : (isBusy ? 'VPN 正在启动' : '准备连接');

    final routeMode = LaunchRouteMode.fromOptions(_launchOptions);

    return Scaffold(
      appBar: AppBar(
        title: const Text('OPENPPP2'),
        centerTitle: true,
      ),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
          children: [
            HomeStatusCard(
              statusText: statusTitle,
              detailText: statusDetail,
              isConnected: isActive,
              isBusy: isBusy,
              buttonLabel: isVpnLive ? '停止' : '连接',
              buttonEnabled: _state != VpnState.disconnecting,
              uploadText: _formatSpeed(_stats.txSpeedBytes),
              downloadText: _formatSpeed(_stats.rxSpeedBytes),
              allowLan: _launchOptions['allowLan'] == true,
              blockQuic: _launchOptions['blockQuic'] == true,
              routeMode: routeMode,
              onConnect: _toggleConnection,
              onAllowLanChanged: _active == null
                  ? null
                  : (v) => _updateLaunchOption((o) {
                        o['allowLan'] = v;
                      }),
              onBlockQuicChanged: _active == null
                  ? null
                  : (v) => _updateLaunchOption((o) {
                        o['blockQuic'] = v;
                      }),
              onRouteModeChanged: _active == null
                  ? null
                  : (mode) => _updateLaunchOption((o) {
                        final next = LaunchRouteMode.applyTo(o, mode);
                        o
                          ..clear()
                          ..addAll(next);
                      }),
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                Text(
                  '配置文件',
                  style: theme.textTheme.titleSmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const Spacer(),
                PopupMenuButton<String>(
                  icon: const Icon(Icons.add_circle_outline),
                  tooltip: '添加配置',
                  onSelected: (value) {
                    if (value == 'new') _addProfile();
                  },
                  itemBuilder: (_) => const [
                    PopupMenuItem(
                      value: 'new',
                      child: ListTile(
                        leading: Icon(Icons.add_rounded),
                        title: Text('新增配置'),
                        contentPadding: EdgeInsets.zero,
                        dense: true,
                      ),
                    ),
                  ],
                ),
              ],
            ),
            const SizedBox(height: 6),
            GroupedProfileList(
              profiles: _profiles,
              activeId: _active?.id,
              shrinkWrap: true,
              maxHeight: MediaQuery.sizeOf(context).height * 0.38,
              onTap: _applyProfile,
              onApply: _applyProfile,
              onEdit: _editProfile,
              onTogglePin: _togglePin,
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

bool mapEquals(Map<String, dynamic> a, Map<String, dynamic> b) {
  if (a.length != b.length) return false;
  for (final key in a.keys) {
    if (!b.containsKey(key)) return false;
    final av = a[key];
    final bv = b[key];
    if (av is Map && bv is Map) {
      if (!mapEquals(
        Map<String, dynamic>.from(av),
        Map<String, dynamic>.from(bv),
      )) {
        return false;
      }
    } else if (av != bv) {
      return false;
    }
  }
  return true;
}
