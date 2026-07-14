import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../models/config_profile.dart';
import '../models/launch_route_mode.dart';
import '../runtime/runtime_controls.dart';
import '../runtime/runtime_snapshot.dart';
import '../runtime/runtime_store.dart';
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
  late final RuntimeStore _runtimeStore;

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
    _runtimeStore = _vpnService.runtimeStore;
    _runtimeStore.addListener(_runtimeChanged);
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

  void _runtimeChanged() {
    if (!mounted) return;
    final phase = _runtimeStore.state.phase;
    setState(() {
      if (phase == RuntimePhase.connected) {
        _connectedAt ??= DateTime.now();
        _connectWatchdogTimer?.cancel();
        _startDurationTimer();
      } else if (phase == RuntimePhase.idle || phase == RuntimePhase.failed) {
        _connectedAt = null;
        _durationTimer?.cancel();
        _duration = '00:00:00';
      } else if (phase == RuntimePhase.reconnecting) {
        _connectedAt = null;
      }
    });
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
    if (ls == _linkState) return;
    setState(() => _linkState = ls);
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
      if (state == VpnState.disconnected) {
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
    switch (controlsFor(_runtimeStore.state.phase).action) {
      case RuntimeConnectionAction.cancel:
      case RuntimeConnectionAction.stop:
      case RuntimeConnectionAction.forceStop:
        await _stopVpnForDebug();
        return;
      case RuntimeConnectionAction.none:
        return;
      case RuntimeConnectionAction.start:
      case RuntimeConnectionAction.retry:
        break;
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
      if (!mounted) {
        timer.cancel();
        return;
      }
      final phase = _runtimeStore.state.phase;
      if (phase == RuntimePhase.connected) {
        timer.cancel();
        return;
      }
      if (controlsFor(phase).action != RuntimeConnectionAction.cancel) {
        timer.cancel();
        return;
      }
      final log = await _vpnService.readLog();
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
      if (!mounted ||
          controlsFor(_runtimeStore.state.phase).action !=
              RuntimeConnectionAction.cancel) {
        return;
      }
      setState(() {
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
  }

  Future<void> _applyProfile(ConfigProfile profile) async {
    if (profile.id == _active?.id) return;
    await _store.setActive(profile.id);
    await _refreshStore();
    if (!mounted) return;
    if (!controlsFor(_runtimeStore.state.phase).configEditable) {
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
    if (!controlsFor(_runtimeStore.state.phase).configEditable) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('快捷设置已保存，重连后生效')),
      );
    }
  }

  String _getStateText() {
    return controlsFor(_runtimeStore.state.phase).statusLabel;
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _stateSub?.cancel();
    _statsSub?.cancel();
    _errorSub?.cancel();
    _linkStateSub?.cancel();
    _storeSub?.cancel();
    _runtimeStore.removeListener(_runtimeChanged);
    _connectWatchdogTimer?.cancel();
    _logPollTimer?.cancel();
    _durationTimer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final controls = controlsFor(_runtimeStore.state.phase);
    final statusTitle = controls.statusLabel;
    final statusDetail =
        controls.isConnected ? _duration : controls.detailLabel;

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
              isConnected: controls.isConnected,
              isBusy: controls.isBusy,
              buttonLabel: controls.buttonLabel,
              buttonEnabled: controls.buttonEnabled,
              uploadText: _formatSpeed(_stats.txSpeedBytes),
              downloadText: _formatSpeed(_stats.rxSpeedBytes),
              allowLan: _launchOptions['allowLan'] == true,
              blockQuic: _launchOptions['blockQuic'] == true,
              routeMode: routeMode,
              onConnect: _toggleConnection,
              onAllowLanChanged: _active == null || !controls.configEditable
                  ? null
                  : (v) => _updateLaunchOption((o) {
                        o['allowLan'] = v;
                      }),
              onBlockQuicChanged: _active == null || !controls.configEditable
                  ? null
                  : (v) => _updateLaunchOption((o) {
                        o['blockQuic'] = v;
                      }),
              onRouteModeChanged: _active == null || !controls.configEditable
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
                  onSelected: controls.configEditable
                      ? (value) {
                          if (value == 'new') _addProfile();
                        }
                      : null,
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
              onTap: controls.configEditable ? _applyProfile : null,
              onApply: controls.configEditable ? _applyProfile : null,
              onEdit: controls.configEditable ? _editProfile : null,
              onTogglePin: controls.configEditable ? _togglePin : null,
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
