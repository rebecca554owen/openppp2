import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../models/config_profile.dart';
import '../services/profile_store.dart';
import '../vpn_service.dart';
import '../widgets/debug_panel.dart';
import 'select_profile_page.dart';

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
  ConfigProfile? _active;
  DateTime? _connectedAt;
  String _duration = '00:00:00';
  String? _lastError;
  bool _debugPanelEnabled = false;
  String _debugLog = '';
  String _logPath = '';
  int _linkState = 6; // APP_UNINIT
  Timer? _linkPollTimer;

  Timer? _durationTimer;
  Timer? _connectWatchdogTimer;
  Timer? _statePollTimer;
  Timer? _statsPollTimer;
  Timer? _logPollTimer;

  StreamSubscription<VpnState>? _stateSub;
  StreamSubscription<VpnStatistics>? _statsSub;
  StreamSubscription<String>? _errorSub;
  StreamSubscription<void>? _storeSub;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _vpnService.init();
    _stateSub = _vpnService.stateStream.listen(_applyState);
    _statsSub = _vpnService.statsStream.listen((stats) {
      // Statistics no longer flip the UI to "connected" on their own:
      // upstream advice is to rely on get_link_state() ESTABLISHED.
      if (!mounted) return;
      setState(() => _stats = stats);
    });
    _errorSub = _vpnService.errorStream.listen((error) {
      if (!mounted) return;
      _connectWatchdogTimer?.cancel();
      setState(() => _lastError = error);
      unawaited(_showErrorDialog(error));
    });
    _storeSub = _store.changes.listen((_) => _refreshActive());

    unawaited(_refreshActive());
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
    // Real link-state poller (1s). Drives the connecting->connected flip and
    // catches the case where the service thinks it's connected but the
    // tunnel never established.
    _linkPollTimer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (_state == VpnState.disconnected || _state == VpnState.disconnecting) {
        if (_linkState != 6) setState(() => _linkState = 6);
        return;
      }
      unawaited(_refreshLinkState());
    });
  }

  Future<void> _refreshLinkState() async {
    final ls = await _vpnService.getLinkState();
    if (!mounted) return;
    final wasEstablished = _linkState == 0;
    setState(() => _linkState = ls);
    if (ls == 0) {
      // ESTABLISHED → real connected
      if (_state != VpnState.connected) {
        _connectWatchdogTimer?.cancel();
        _applyState(VpnState.connected);
      }
    } else if (wasEstablished && _state == VpnState.connected) {
      // Tunnel was established but dropped (UNKNOWN/RECONNECTING/CONNECTING etc.)
      _applyState(VpnState.connecting);
      _connectedAt = null;
    }
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      unawaited(_refreshStartupState());
      unawaited(_refreshActive());
      unawaited(_loadDebugPanelEnabled());
    }
  }

  Future<void> _refreshActive() async {
    final p = await _store.getActive();
    if (!mounted) return;
    setState(() => _active = p);
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
    // Upstream guidance: the service can report "connected" before the link is
    // actually established; only flip to Connected when get_link_state()
    // reports ESTABLISHED (0). Otherwise stay in Connecting.
    var effective = state;
    if (state == VpnState.connected && _linkState != 0) {
      effective = VpnState.connecting;
    }
    setState(() {
      _state = effective;
      if (effective == VpnState.connected) {
        _connectedAt ??= DateTime.now();
        _connectWatchdogTimer?.cancel();
        _startDurationTimer();
      } else if (effective == VpnState.disconnected) {
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

    final profile = _active;
    if (profile == null || profile.json.trim().isEmpty) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('请先在「配置文件」页中添加并选择一个配置')),
      );
      _openSelectProfile();
      return;
    }
    try {
      await _vpnService.clearLog();
      // Per-profile launch options: each profile carries its own DNS / Geo
      // bypass / TUN parameters. Falls back to legacy global options if a
      // profile predates the per-profile feature.
      final options = await _store.getProfileOptions(profile.id);
      // NOTE: `autoAppendApps` is a *system* HTTP proxy toggle (handled by
      // PppVpnService via VpnService.Builder.setHttpProxy), not a "merge all
      // installed apps into the per-app whitelist" flag -- doing the latter
      // would silently break user-configured app splitting.
      // Splice options.dnsConfig / options.geoRules into the AppConfiguration
      // JSON so the native engine receives the user's friendly form values.
      final mergedJson = ProfileStore.effectiveJson(profile.json, options);
      await _vpnService.connect(mergedJson, vpnOptions: options);
      _startConnectWatchdog();
    } catch (e) {
      if (!mounted) return;
      final error = e.toString();
      setState(() => _lastError = error);
      await _showErrorDialog(error);
    }
  }

  // Heartbeat-based watchdog. The native engine can legitimately take
  // 60+s before issuing onStarted when geo-rules are enabled (parsing
  // GeoIP.dat / GeoSite.dat is synchronous on the run() thread). The
  // file log doesn't grow during that window either, so a fixed timer
  // OR a log-growth timer would both mis-fire. Instead we trust the
  // link-state-poller heartbeat in :vpn (writes once a second). As
  // long as that heartbeat is fresh, the engine is alive and we keep
  // waiting. _connectMaxSeconds caps the total wait.
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
      final log = await _vpnService.readLog();
      // Already connected? bail out cleanly.
      if (log.contains('onStarted key=') ||
          log.contains('VPN started with key=') ||
          log.contains('statistics=')) {
        timer.cancel();
        if (!mounted) return;
        _applyState(VpnState.connected);
        return;
      }
      // Liveness signal: :vpn writes the link-state file once a second.
      // If the heartbeat is fresh (<5s) we assume the engine is still
      // making progress -- even when log/link-state values stay the same
      // (e.g. blocked inside open_switcher parsing GeoIP.dat for ~60s).
      final hbAgeMs = await _vpnService.getVpnHeartbeatAgeMs();
      final hbStale = hbAgeMs < 0 || hbAgeMs > 8000;
      final totalSec = DateTime.now().difference(startedAt).inSeconds;
      if (!hbStale && totalSec < _connectMaxSeconds) {
        return; // engine alive, keep waiting
      }
      timer.cancel();
      final hasRunCalled = log.contains('vpnThread started');
      final reason = totalSec >= _connectMaxSeconds
          ? '超过 ${_connectMaxSeconds}s 上限'
          : ':vpn 心跳已停 ${(hbAgeMs / 1000).toStringAsFixed(1)}s';
      final error = log.trim().isEmpty
          ? '连接超时（$reason）：VPN Service 没有返回状态，也没有生成日志。'
          : hasRunCalled
              ? '连接超时（$reason）：native 引擎已启动但未完成握手。\n请检查所选配置的服务器地址、密钥与网络连通性。'
              : '连接超时（$reason）：VPN 未进入已连接状态。';
      if (!mounted || _state != VpnState.connecting) return;
      setState(() {
        _state = VpnState.disconnected;
        _lastError = error;
      });
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

  Future<void> _openSelectProfile() async {
    await Navigator.of(context).push(
      MaterialPageRoute(builder: (_) => const SelectProfilePage()),
    );
    if (mounted) await _refreshActive();
  }

  String _connectingLabel() {
    switch (_linkState) {
      case 0:
        return 'Connecting...'; // shouldn't reach here
      case 4:
        return 'Reconnecting...';
      case 5:
        return 'Handshaking...';
      case 2:
        return 'Initializing client...';
      case 3:
        return 'Initializing exchanger...';
      case 6:
        return 'Starting engine...';
      default:
        return 'Connecting...';
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

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _stateSub?.cancel();
    _statsSub?.cancel();
    _errorSub?.cancel();
    _storeSub?.cancel();
    _connectWatchdogTimer?.cancel();
    _statePollTimer?.cancel();
    _statsPollTimer?.cancel();
    _logPollTimer?.cancel();
    _linkPollTimer?.cancel();
    _durationTimer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isActive = _state == VpnState.connected;
    final isBusy =
        _state == VpnState.connecting || _state == VpnState.disconnecting;

    final accent = isActive
        ? const Color(0xFF22C55E) // green when on
        : const Color(0xFFEF4444); // red when off
    final accentSoft = accent.withValues(alpha: 0.12);
    final accentSofter = accent.withValues(alpha: 0.06);

    final statusTitle = isActive
        ? 'Connected'
        : (_state == VpnState.connecting
            ? _connectingLabel()
            : (_state == VpnState.disconnecting ? 'Disconnecting...' : 'Not Connected'));
    return Scaffold(
      backgroundColor: theme.scaffoldBackgroundColor,
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.fromLTRB(20, 16, 20, 24),
          children: [
            _buildHeader(theme),
            const SizedBox(height: 8),
            Center(
              child: _RadialPowerButton(
                color: accent,
                softColor: accentSoft,
                softerColor: accentSofter,
                isBusy: isBusy,
                onTap: _state == VpnState.disconnecting ? null : _toggleConnection,
                isOn: isActive,
              ),
            ),
            const SizedBox(height: 18),
            Center(
              child: Text(
                statusTitle,
                style: theme.textTheme.titleLarge?.copyWith(
                  fontWeight: FontWeight.w700,
                ),
              ),
            ),
            const SizedBox(height: 4),
            Center(
              child: RichText(
                text: TextSpan(
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                  children: [
                    const TextSpan(text: 'VPN is '),
                    TextSpan(
                      text: isActive ? 'ON' : 'OFF',
                      style: TextStyle(
                        color: isActive ? const Color(0xFF22C55E) : const Color(0xFFEF4444),
                        fontWeight: FontWeight.w800,
                      ),
                    ),
                  ],
                ),
              ),
            ),
            if (isActive) ...[
              const SizedBox(height: 6),
              Center(
                child: Text(
                  _duration,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    fontFeatures: [const FontFeature.tabularFigures()],
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
            ],
            const SizedBox(height: 24),
            Padding(
              padding: const EdgeInsets.only(left: 4, bottom: 8),
              child: Text(
                isActive ? 'Connected to' : 'Connect to',
                style: theme.textTheme.bodyMedium?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
            ),
            _buildLocationCard(theme, isActive),
            if (isActive) ...[
              const SizedBox(height: 16),
              Row(
                children: [
                  Expanded(
                    child: _StatCard(
                      icon: Icons.arrow_upward_rounded,
                      label: '上行',
                      value: _formatSpeed(_stats.txSpeedBytes),
                      subtitle: '总 ${_formatBytes(_stats.outBytes)}',
                      color: const Color(0xFFF59E0B),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: _StatCard(
                      icon: Icons.arrow_downward_rounded,
                      label: '下行',
                      value: _formatSpeed(_stats.rxSpeedBytes),
                      subtitle: '总 ${_formatBytes(_stats.inBytes)}',
                      color: const Color(0xFF3B82F6),
                    ),
                  ),
                ],
              ),
            ],
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

  Widget _buildHeader(ThemeData theme) {
    return Padding(
      padding: const EdgeInsets.only(top: 4, bottom: 12),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.location_on_rounded, size: 20, color: theme.colorScheme.primary),
          const SizedBox(width: 6),
          Text(
            'OPENPPP2',
            style: theme.textTheme.titleMedium?.copyWith(
              fontWeight: FontWeight.w900,
              letterSpacing: 1.2,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildLocationCard(ThemeData theme, bool isActive) {
    final p = _active;
    final name = p?.name ?? 'No profile';
    final sub = (p?.subtitle.isNotEmpty == true)
        ? p!.subtitle
        : (p?.serverEndpoint ?? '点击选择一个配置');

    return Material(
      color: theme.colorScheme.surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: BorderSide(color: theme.colorScheme.outlineVariant),
      ),
      child: InkWell(
        borderRadius: BorderRadius.circular(16),
        onTap: _openSelectProfile,
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
          child: Row(
            children: [
              Container(
                width: 36,
                height: 36,
                decoration: BoxDecoration(
                  color: theme.colorScheme.primary.withValues(alpha: 0.1),
                  shape: BoxShape.circle,
                ),
                alignment: Alignment.center,
                child: Text(
                  p?.flag.isNotEmpty == true ? p!.flag : '🌐',
                  style: const TextStyle(fontSize: 20),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      name,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: theme.textTheme.titleSmall?.copyWith(
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      sub,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ],
                ),
              ),
              const Icon(Icons.chevron_right_rounded),
            ],
          ),
        ),
      ),
    );
  }
}

class _RadialPowerButton extends StatelessWidget {
  final Color color;
  final Color softColor;
  final Color softerColor;
  final bool isOn;
  final bool isBusy;
  final VoidCallback? onTap;

  const _RadialPowerButton({
    required this.color,
    required this.softColor,
    required this.softerColor,
    required this.isOn,
    required this.isBusy,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: SizedBox(
        width: 240,
        height: 240,
        child: Stack(
          alignment: Alignment.center,
          children: [
            Container(
              width: 220,
              height: 220,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: softerColor,
              ),
            ),
            Container(
              width: 170,
              height: 170,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: softColor,
              ),
            ),
            Container(
              width: 124,
              height: 124,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: color,
                boxShadow: [
                  BoxShadow(
                    color: color.withValues(alpha: 0.45),
                    blurRadius: 28,
                    spreadRadius: 2,
                  ),
                ],
              ),
              child: Center(
                child: isBusy
                    ? const SizedBox(
                        width: 42,
                        height: 42,
                        child: CircularProgressIndicator(
                          color: Colors.white,
                          strokeWidth: 3,
                        ),
                      )
                    : const Icon(
                        Icons.power_settings_new_rounded,
                        color: Colors.white,
                        size: 56,
                      ),
              ),
            ),
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
        padding: const EdgeInsets.all(14),
        child: Column(
          children: [
            Icon(icon, color: color, size: 22),
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
