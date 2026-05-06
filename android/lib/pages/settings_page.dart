import 'dart:convert';
import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../vpn_service.dart';
import '../widgets/debug_panel.dart';

class SettingsPage extends StatefulWidget {
  const SettingsPage({super.key});

  static const _configKey = 'vpn_config_json';
  static const _optionsKey = 'vpn_options_json';
  static const _debugPanelKey = 'debug_panel_enabled';

  static Future<String?> getConfig() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_configKey);
  }

  static Future<Map<String, dynamic>> getVpnOptions() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_optionsKey);
    if (raw == null || raw.isEmpty) {
      return Map<String, dynamic>.from(_defaultOptions);
    }
    final decoded = jsonDecode(raw);
    if (decoded is Map) {
      return Map<String, dynamic>.from(decoded);
    }
    return Map<String, dynamic>.from(_defaultOptions);
  }

  static Future<bool> getDebugPanelEnabled() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getBool(_debugPanelKey) ?? false;
  }

  static const _defaultOptions = <String, dynamic>{
    'tunIp': '10.0.0.2',
    'tunMask': '255.255.255.0',
    'tunPrefix': 24,
    'gateway': '10.0.0.1',
    'route': '0.0.0.0',
    'routePrefix': 0,
    'dns1': '8.8.8.8',
    'dns2': '8.8.4.4',
    'mtu': 1400,
    'mark': 0,
    'mux': 0,
    'vnet': false,
    'blockQuic': false,
    'staticMode': false,
  };

  static const _defaultConfig = '''{
  "concurrent": 1,
  "cdn": [80, 443],
  "key": {
    "kf": 154543927,
    "kx": 128,
    "kl": 10,
    "kh": 12,
    "protocol": "aes-128-cfb",
    "protocol-key": "N6HMzdUs7IUnYHwq",
    "transport": "aes-256-cfb",
    "transport-key": "HWFweXu2g5RVMEpy",
    "masked": false,
    "plaintext": false,
    "delta-encode": false,
    "shuffle-data": false
  },
  "ip": {
    "public": "192.168.0.24",
    "interface": "192.168.0.24"
  },
  "vmem": {
    "size": 0,
    "path": "./"
  },
  "server": {
    "node": 1,
    "log": "./ppp.log",
    "subnet": true,
    "mapping": true,
    "backend": "",
    "backend-key": ""
  },
  "tcp": {
    "inactive": {
      "timeout": 300
    },
    "connect": {
      "timeout": 5
    },
    "listen": {
      "port": 20000
    },
    "turbo": true,
    "backlog": 511,
    "fast-open": true
  },
  "udp": {
    "inactive": {
      "timeout": 72
    },
    "dns": {
      "timeout": 4,
      "redirect": "0.0.0.0"
    },
    "listen": {
      "port": 20000
    },
    "static": {
      "keep-alived": [1, 5],
      "dns": true,
      "quic": true,
      "icmp": true,
      "server": "127.0.0.1:20000"
    }
  },
  "websocket": {
    "host": "",
    "path": "/",
    "listen": {
      "ws": 0,
      "wss": 0
    },
    "ssl": {
      "certificate-file": "./cert.pem",
      "certificate-chain-file": "./fullchain.pem",
      "certificate-key-file": "./key.pem",
      "certificate-key-password": "test",
      "ciphersuites": "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
    },
    "verify-peer": true,
    "http": {
      "error": {
        "root": "wwwroot/"
      },
      "request": {
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "X-Powered-By": "ASP.NET",
        "Content-Type": "text/html; charset=utf-8",
        "Server": "Microsoft-IIS/10.0"
      }
    }
  },
  "client": {
    "guid": "{F4569420-4E49-4CBA-9C36-94E722C8E363}",
    "server": "ppp://192.168.0.24:20000/",
    "bandwidth": 0,
    "reconnections": {
      "timeout": 5
    },
    "paper-airplane": {
      "tcp": true
    },
    "http-proxy": {
      "bind": "127.0.0.1",
      "port": 8080
    },
    "socks-proxy": {
      "bind": "127.0.0.1",
      "port": 1080
    },
    "mappings": []
  }
}''';

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  final _vpnService = VpnService();
  final _configController = TextEditingController();
  final _tunIpController = TextEditingController();
  final _tunMaskController = TextEditingController();
  final _tunPrefixController = TextEditingController();
  final _gatewayController = TextEditingController();
  final _routeController = TextEditingController();
  final _routePrefixController = TextEditingController();
  final _dns1Controller = TextEditingController();
  final _dns2Controller = TextEditingController();
  final _mtuController = TextEditingController();
  final _markController = TextEditingController();
  final _muxController = TextEditingController();
  final _bypassIpListController = TextEditingController();
  final _dnsRulesListController = TextEditingController();
  bool _vnet = false;
  bool _blockQuic = false;
  bool _staticMode = false;
  bool _debugPanelEnabled = false;
  bool _loading = true;
  VpnState _state = VpnState.disconnected;
  String _debugLog = '';
  String _logPath = '';
  Timer? _debugPollTimer;
  StreamSubscription<VpnState>? _stateSub;

  @override
  void initState() {
    super.initState();
    _vpnService.init();
    _stateSub = _vpnService.stateStream.listen((state) {
      if (!mounted) return;
      setState(() => _state = state);
    });
    _loadConfig();
  }

  Future<void> _loadConfig() async {
    final prefs = await SharedPreferences.getInstance();
    final config = prefs.getString(SettingsPage._configKey) ?? SettingsPage._defaultConfig;
    final options = await SettingsPage.getVpnOptions();
    final debugPanelEnabled = await SettingsPage.getDebugPanelEnabled();
    _configController.text = config;
    _tunIpController.text = options['tunIp']?.toString() ?? '10.0.0.2';
    _tunMaskController.text = options['tunMask']?.toString() ?? '255.255.255.0';
    _tunPrefixController.text = options['tunPrefix']?.toString() ?? '24';
    _gatewayController.text = options['gateway']?.toString() ?? '10.0.0.1';
    _routeController.text = options['route']?.toString() ?? '0.0.0.0';
    _routePrefixController.text = options['routePrefix']?.toString() ?? '0';
    _dns1Controller.text = options['dns1']?.toString() ?? '8.8.8.8';
    _dns2Controller.text = options['dns2']?.toString() ?? '8.8.4.4';
    _mtuController.text = options['mtu']?.toString() ?? '1400';
    _markController.text = options['mark']?.toString() ?? '0';
    _muxController.text = options['mux']?.toString() ?? '0';
    _bypassIpListController.text = options['bypassIpList']?.toString() ?? '';
    _dnsRulesListController.text = options['dnsRulesList']?.toString() ?? '';
    _vnet = options['vnet'] == true;
    _blockQuic = options['blockQuic'] == true;
    _staticMode = options['staticMode'] == true;
    _debugPanelEnabled = debugPanelEnabled;
    _state = _vpnService.currentState;
    if (_debugPanelEnabled) {
      _startDebugPolling();
      unawaited(_refreshDebugInfo());
    }
    setState(() => _loading = false);
  }

  Map<String, dynamic> _readOptions() {
    return {
      'tunIp': _tunIpController.text.trim(),
      'tunMask': _tunMaskController.text.trim(),
      'tunPrefix': int.tryParse(_tunPrefixController.text.trim()) ?? 24,
      'gateway': _gatewayController.text.trim(),
      'route': _routeController.text.trim(),
      'routePrefix': int.tryParse(_routePrefixController.text.trim()) ?? 0,
      'dns1': _dns1Controller.text.trim(),
      'dns2': _dns2Controller.text.trim(),
      'mtu': int.tryParse(_mtuController.text.trim()) ?? 1400,
      'mark': int.tryParse(_markController.text.trim()) ?? 0,
      'mux': int.tryParse(_muxController.text.trim()) ?? 0,
      'vnet': _vnet,
      'blockQuic': _blockQuic,
      'staticMode': _staticMode,
      'bypassIpList': _bypassIpListController.text.trim(),
      'dnsRulesList': _dnsRulesListController.text.trim(),
    };
  }

  Future<void> _saveConfig() async {
    try {
      jsonDecode(_configController.text);
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('JSON 格式错误: $e')),
        );
      }
      return;
    }
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(SettingsPage._configKey, _configController.text);
    await prefs.setString(SettingsPage._optionsKey, jsonEncode(_readOptions()));
    await prefs.setBool(SettingsPage._debugPanelKey, _debugPanelEnabled);
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('配置已保存')),
      );
    }
  }

  Future<void> _resetConfig() async {
    _configController.text = SettingsPage._defaultConfig;
    final options = Map<String, dynamic>.from(SettingsPage._defaultOptions);
    _tunIpController.text = options['tunIp'].toString();
    _tunMaskController.text = options['tunMask'].toString();
    _tunPrefixController.text = options['tunPrefix'].toString();
    _gatewayController.text = options['gateway'].toString();
    _routeController.text = options['route'].toString();
    _routePrefixController.text = options['routePrefix'].toString();
    _dns1Controller.text = options['dns1'].toString();
    _dns2Controller.text = options['dns2'].toString();
    _mtuController.text = options['mtu'].toString();
    _markController.text = options['mark'].toString();
    _muxController.text = options['mux'].toString();
    _bypassIpListController.text = options['bypassIpList']?.toString() ?? '';
    _dnsRulesListController.text = options['dnsRulesList']?.toString() ?? '';
    setState(() {
      _vnet = options['vnet'] == true;
      _blockQuic = options['blockQuic'] == true;
      _staticMode = options['staticMode'] == true;
      _debugPanelEnabled = false;
    });
    await _saveConfig();
  }

  void _setDebugPanelEnabled(bool value) {
    setState(() => _debugPanelEnabled = value);
    if (value) {
      _startDebugPolling();
      unawaited(_refreshDebugInfo());
    } else {
      _debugPollTimer?.cancel();
      _debugPollTimer = null;
    }
    unawaited(_saveDebugPanelEnabled(value));
  }

  Future<void> _saveDebugPanelEnabled(bool value) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(SettingsPage._debugPanelKey, value);
  }

  void _startDebugPolling() {
    _debugPollTimer?.cancel();
    _debugPollTimer = Timer.periodic(const Duration(seconds: 2), (_) {
      unawaited(_refreshDebugInfo());
    });
  }

  Future<void> _refreshDebugInfo() async {
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
    await _vpnService.disconnect();
    await _refreshDebugInfo();
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
    _configController.dispose();
    _tunIpController.dispose();
    _tunMaskController.dispose();
    _tunPrefixController.dispose();
    _gatewayController.dispose();
    _routeController.dispose();
    _routePrefixController.dispose();
    _dns1Controller.dispose();
    _dns2Controller.dispose();
    _mtuController.dispose();
    _markController.dispose();
    _muxController.dispose();
    _bypassIpListController.dispose();
    _dnsRulesListController.dispose();
    _debugPollTimer?.cancel();
    _stateSub?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('客户端配置'),
        centerTitle: true,
        actions: [
          IconButton(
            icon: const Icon(Icons.restore),
            tooltip: '恢复默认',
            onPressed: _resetConfig,
          ),
          IconButton(
            icon: const Icon(Icons.save),
            tooltip: '保存',
            onPressed: _saveConfig,
          ),
        ],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              padding: const EdgeInsets.all(16),
              children: [
                Text('TUN 参数', style: Theme.of(context).textTheme.titleMedium),
                const SizedBox(height: 12),
                _TextField(controller: _tunIpController, label: 'TUN IP'),
                _TextField(controller: _tunMaskController, label: 'TUN Mask'),
                _TextField(controller: _tunPrefixController, label: 'TUN Prefix', keyboardType: TextInputType.number),
                _TextField(controller: _gatewayController, label: 'Gateway'),
                _TextField(controller: _routeController, label: 'Route'),
                _TextField(controller: _routePrefixController, label: 'Route Prefix', keyboardType: TextInputType.number),
                _TextField(controller: _dns1Controller, label: 'DNS 1'),
                _TextField(controller: _dns2Controller, label: 'DNS 2'),
                _TextField(controller: _mtuController, label: 'MTU', keyboardType: TextInputType.number),
                _TextField(controller: _markController, label: 'Mark', keyboardType: TextInputType.number),
                _TextField(controller: _muxController, label: 'Mux', keyboardType: TextInputType.number),
                SwitchListTile(
                  value: _vnet,
                  title: const Text('VNet'),
                  onChanged: (value) => setState(() => _vnet = value),
                ),
                SwitchListTile(
                  value: _blockQuic,
                  title: const Text('Block QUIC'),
                  onChanged: (value) => setState(() => _blockQuic = value),
                ),
                SwitchListTile(
                  value: _staticMode,
                  title: const Text('Static Mode'),
                  onChanged: (value) => setState(() => _staticMode = value),
                ),
                const SizedBox(height: 16),
                Text('Bypass IP 列表', style: Theme.of(context).textTheme.titleMedium),
                const SizedBox(height: 4),
                Text('每行一个 IP 或 CIDR（如 192.168.0.0/24），留空表示不过滤', style: Theme.of(context).textTheme.bodySmall),
                const SizedBox(height: 8),
                SizedBox(
                  height: 120,
                  child: TextField(
                    controller: _bypassIpListController,
                    maxLines: null,
                    expands: true,
                    textAlignVertical: TextAlignVertical.top,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                    decoration: InputDecoration(
                      border: OutlineInputBorder(borderRadius: BorderRadius.circular(8)),
                      contentPadding: const EdgeInsets.all(12),
                      hintText: '192.168.0.0/24\n10.0.0.0/8\n# 注释行',
                    ),
                  ),
                ),
                const SizedBox(height: 16),
                Text('DNS 规则列表', style: Theme.of(context).textTheme.titleMedium),
                const SizedBox(height: 4),
                Text('每行一个 DNS 规则，留空表示不加载', style: Theme.of(context).textTheme.bodySmall),
                const SizedBox(height: 8),
                SizedBox(
                  height: 120,
                  child: TextField(
                    controller: _dnsRulesListController,
                    maxLines: null,
                    expands: true,
                    textAlignVertical: TextAlignVertical.top,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                    decoration: InputDecoration(
                      border: OutlineInputBorder(borderRadius: BorderRadius.circular(8)),
                      contentPadding: const EdgeInsets.all(12),
                      hintText: '8.8.8.8\n1.1.1.1',
                    ),
                  ),
                ),
                SwitchListTile(
                  value: _debugPanelEnabled,
                  title: const Text('显示调试面板'),
                  subtitle: const Text('显示状态、日志、复制、清空和停止按钮'),
                  onChanged: _setDebugPanelEnabled,
                ),
                if (_debugPanelEnabled) ...[
                  const SizedBox(height: 8),
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
                const SizedBox(height: 16),
                Text('OpenPPP2 JSON', style: Theme.of(context).textTheme.titleMedium),
                const SizedBox(height: 8),
                SizedBox(
                  height: 360,
                  child: TextField(
                    controller: _configController,
                    maxLines: null,
                    expands: true,
                    textAlignVertical: TextAlignVertical.top,
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 12,
                    ),
                    decoration: InputDecoration(
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(8),
                      ),
                      contentPadding: const EdgeInsets.all(12),
                    ),
                  ),
                ),
                const SizedBox(height: 16),
                FilledButton.icon(
                  onPressed: _saveConfig,
                  icon: const Icon(Icons.save),
                  label: const Text('保存配置'),
                ),
              ],
            ),
    );
  }
}

class _TextField extends StatelessWidget {
  final TextEditingController controller;
  final String label;
  final TextInputType? keyboardType;

  const _TextField({
    required this.controller,
    required this.label,
    this.keyboardType,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: TextField(
        controller: controller,
        keyboardType: keyboardType,
        decoration: InputDecoration(
          labelText: label,
          border: const OutlineInputBorder(),
        ),
      ),
    );
  }
}
