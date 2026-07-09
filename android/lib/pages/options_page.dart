import 'dart:async';
import 'package:flutter/material.dart';
import '../models/config_profile.dart';
import '../models/launch_route_mode.dart';
import '../services/profile_store.dart';
import '../widgets/app_section_card.dart';
import 'options_advanced_page.dart';

/// Per-profile launch options aligned with the iOS Options screen layout.
class OptionsPage extends StatefulWidget {
  const OptionsPage({super.key});

  @override
  State<OptionsPage> createState() => _OptionsPageState();
}

class _OptionsPageState extends State<OptionsPage> {
  final _store = ProfileStore();

  final _tunIp = TextEditingController();
  final _tunMask = TextEditingController();
  final _tunPrefix = TextEditingController();
  final _gateway = TextEditingController();
  final _mtu = TextEditingController();
  final _route = TextEditingController();
  final _routePrefix = TextEditingController();
  final _dns1 = TextEditingController();
  final _dns2 = TextEditingController();
  final _dnsRulesList = TextEditingController();
  final _bypassIpList = TextEditingController();
  final _dnsDomestic = TextEditingController();
  final _dnsForeign = TextEditingController();
  final _dnsEcsOverride = TextEditingController();
  final _dnsStunCandidates = TextEditingController();
  final _geoCountry = TextEditingController();
  final _geoIpDat = TextEditingController();
  final _geoSiteDat = TextEditingController();
  final _httpProxyPort = TextEditingController(text: '8080');
  final _socksProxyPort = TextEditingController(text: '1080');

  bool _allowLan = false;
  bool _blockQuic = false;
  bool _dnsInterceptUnmatched = true;
  bool _dnsFakeIpEnabled = false;
  final _dnsFakeIpRange = TextEditingController(text: '198.18.0.1/16');
  bool _dnsEcsEnabled = true;
  bool _dnsTlsVerifyPeer = true;
  LaunchRouteMode _routeMode = LaunchRouteMode.geo;

  ConfigProfile? _profile;
  bool _loading = true;
  bool _dirty = false;
  StreamSubscription<void>? _storeSub;

  @override
  void initState() {
    super.initState();
    _storeSub = _store.changes.listen((_) => _reloadIfActiveChanged());
    _load();
  }

  Future<void> _reloadIfActiveChanged() async {
    if (_dirty || !mounted) return;
    final active = await _store.getActive();
    if (active == null) return;
    if (_profile?.id != active.id) {
      await _load();
      return;
    }
    final m = await _store.getProfileOptions(active.id);
    if (!mounted) return;
    _hydrate(m);
    setState(() => _profile = active);
  }

  Future<void> _load() async {
    final active = await _store.getActive();
    if (active == null) {
      if (!mounted) return;
      setState(() {
        _profile = null;
        _loading = false;
      });
      return;
    }
    final m = await _store.getProfileOptions(active.id);
    if (!mounted) return;
    _hydrate(m);
    setState(() {
      _profile = active;
      _loading = false;
      _dirty = false;
    });
  }

  void _hydrate(Map<String, dynamic> m) {
    _tunIp.text = (m['tunIp'] ?? '').toString();
    _tunMask.text = (m['tunMask'] ?? '').toString();
    _tunPrefix.text = (m['tunPrefix'] ?? '24').toString();
    _gateway.text = (m['gateway'] ?? '').toString();
    _route.text = (m['route'] ?? '').toString();
    _routePrefix.text = (m['routePrefix'] ?? '0').toString();
    _dns1.text = (m['dns1'] ?? '').toString();
    _dns2.text = (m['dns2'] ?? '').toString();
    _mtu.text = (m['mtu'] ?? '1400').toString();
    _bypassIpList.text = (m['bypassIpList'] ?? '').toString();
    _dnsRulesList.text = (m['dnsRulesList'] ?? '').toString();
    _allowLan = m['allowLan'] == true;
    _blockQuic = m['blockQuic'] == true;
    _httpProxyPort.text = (m['httpProxyPort'] ?? '8080').toString();
    _socksProxyPort.text = (m['socksProxyPort'] ?? '1080').toString();
    _routeMode = LaunchRouteMode.fromOptions(m);

    final dnsCfg = (m['dnsConfig'] is Map)
        ? Map<String, dynamic>.from(m['dnsConfig'] as Map)
        : <String, dynamic>{};
    _dnsDomestic.text = (dnsCfg['domestic'] ?? '').toString();
    _dnsForeign.text = (dnsCfg['foreign'] ?? '').toString();
    _dnsEcsOverride.text = (dnsCfg['ecsOverrideIp'] ?? '').toString();
    _dnsStunCandidates.text = (dnsCfg['stunCandidates'] ?? '').toString();
    _dnsInterceptUnmatched = dnsCfg['interceptUnmatched'] ?? true;
    _dnsFakeIpEnabled = dnsCfg['fakeIpEnabled'] ?? false;
    _dnsFakeIpRange.text = (dnsCfg['fakeIpRange'] ?? '198.18.0.1/16').toString();
    _dnsEcsEnabled = dnsCfg['ecsEnabled'] ?? true;
    _dnsTlsVerifyPeer = dnsCfg['tlsVerifyPeer'] ?? true;

    final geo = (m['geoRules'] is Map)
        ? Map<String, dynamic>.from(m['geoRules'] as Map)
        : <String, dynamic>{};
    _geoCountry.text = (geo['country'] ?? '').toString();
    _geoIpDat.text = (geo['geoipDat'] ?? '').toString();
    _geoSiteDat.text = (geo['geositeDat'] ?? '').toString();
  }

  Map<String, dynamic> _readForm(Map<String, dynamic> base) {
    var options = Map<String, dynamic>.from(base);
    options
      ..['tunIp'] = _tunIp.text.trim()
      ..['tunMask'] = _tunMask.text.trim()
      ..['tunPrefix'] = int.tryParse(_tunPrefix.text.trim()) ?? 24
      ..['gateway'] = _gateway.text.trim()
      ..['route'] = _route.text.trim()
      ..['routePrefix'] = int.tryParse(_routePrefix.text.trim()) ?? 0
      ..['dns1'] = _dns1.text.trim()
      ..['dns2'] = _dns2.text.trim()
      ..['mtu'] = int.tryParse(_mtu.text.trim()) ?? 1400
      ..['allowLan'] = _allowLan
      ..['blockQuic'] = _blockQuic
      ..['bypassIpList'] = _bypassIpList.text
      ..['dnsRulesList'] = _dnsRulesList.text
      ..['httpProxyPort'] = int.tryParse(_httpProxyPort.text.trim()) ?? 8080
      ..['socksProxyPort'] = int.tryParse(_socksProxyPort.text.trim()) ?? 1080
      ..['dnsConfig'] = {
        'domestic': _dnsDomestic.text.trim(),
        'foreign': _dnsForeign.text.trim(),
        'interceptUnmatched': _dnsInterceptUnmatched,
        'fakeIpEnabled': _dnsFakeIpEnabled,
        'fakeIpRange': _dnsFakeIpRange.text.trim(),
        'ecsEnabled': _dnsEcsEnabled,
        'ecsOverrideIp': _dnsEcsOverride.text.trim(),
        'tlsVerifyPeer': _dnsTlsVerifyPeer,
        'stunCandidates': _dnsStunCandidates.text,
      };
    final geo = (options['geoRules'] is Map)
        ? Map<String, dynamic>.from(options['geoRules'] as Map)
        : <String, dynamic>{};
    geo['country'] = _geoCountry.text.trim();
    geo['geoipDat'] = _geoIpDat.text.trim();
    geo['geositeDat'] = _geoSiteDat.text.trim();
    options['geoRules'] = geo;
    options = LaunchRouteMode.applyTo(options, _routeMode);
    return options;
  }

  void _markDirty() {
    if (!_dirty) setState(() => _dirty = true);
  }

  Future<void> _save({bool showSnack = true}) async {
    final p = _profile;
    if (p == null) return;
    final current = await _store.getProfileOptions(p.id);
    final merged = _readForm(current);
    await _store.setProfileOptions(p.id, merged);
    if (!mounted) return;
    setState(() => _dirty = false);
    if (showSnack) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('「${p.name}」启动参数已保存')),
      );
    }
  }

  Future<void> _reset() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('恢复默认'),
        content: Text('将「${_profile?.name ?? '当前配置'}」的启动参数恢复为默认值？'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('取消'),
          ),
          FilledButton.tonal(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('恢复'),
          ),
        ],
      ),
    );
    if (ok != true) return;
    _hydrate(Map<String, dynamic>.from(ProfileStore.defaultOptions));
    setState(() => _dirty = true);
  }

  @override
  void dispose() {
    _storeSub?.cancel();
    for (final c in [
      _tunIp,
      _tunMask,
      _tunPrefix,
      _gateway,
      _route,
      _routePrefix,
      _dns1,
      _dns2,
      _mtu,
      _bypassIpList,
      _dnsRulesList,
      _dnsDomestic,
      _dnsForeign,
      _dnsEcsOverride,
      _dnsFakeIpRange,
      _dnsStunCandidates,
      _geoCountry,
      _geoIpDat,
      _geoSiteDat,
      _httpProxyPort,
      _socksProxyPort,
    ]) {
      c.dispose();
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      appBar: AppBar(
        title: const Text('启动参数'),
        centerTitle: true,
        actions: [
          IconButton(
            icon: const Icon(Icons.restore_rounded),
            tooltip: '恢复默认',
            onPressed: _profile == null ? null : _reset,
          ),
          IconButton(
            icon: const Icon(Icons.save_rounded),
            tooltip: '保存',
            onPressed: _profile == null || !_dirty ? null : _save,
          ),
        ],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : _profile == null
              ? Center(
                  child: Padding(
                    padding: const EdgeInsets.all(24),
                    child: Text(
                      '请先在「配置文件」页中创建并选择一个配置',
                      textAlign: TextAlign.center,
                      style: theme.textTheme.bodyMedium,
                    ),
                  ),
                )
              : ListView(
                  padding: const EdgeInsets.all(16),
                  children: [
                    _activeBanner(theme),
                    AppSectionCard(
                      title: '代理',
                      icon: Icons.account_tree_rounded,
                      tint: Colors.cyan,
                      children: [
                        Row(
                          children: [
                            Expanded(
                              child: _text(_httpProxyPort, 'HTTP 端口',
                                  keyboardType: TextInputType.number,
                                  onChanged: _markDirty),
                            ),
                            const SizedBox(width: 8),
                            Expanded(
                              child: _text(_socksProxyPort, 'SOCKS 端口',
                                  keyboardType: TextInputType.number,
                                  onChanged: _markDirty),
                            ),
                          ],
                        ),
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          value: _allowLan,
                          title: const Text('允许局域网代理'),
                          subtitle: const Text('HTTP / SOCKS 监听 0.0.0.0'),
                          onChanged: (v) => setState(() {
                            _allowLan = v;
                            _markDirty();
                          }),
                        ),
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          value: _blockQuic,
                          title: const Text('屏蔽 QUIC'),
                          subtitle: const Text('屏蔽 UDP/443 防止 QUIC 绕过'),
                          onChanged: (v) => setState(() {
                            _blockQuic = v;
                            _markDirty();
                          }),
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    AppSectionCard(
                      title: 'DNS',
                      icon: Icons.dns_rounded,
                      children: [
                        Row(
                          children: [
                            Expanded(
                                child: _text(_dns1, 'DNS 1', onChanged: _markDirty)),
                            const SizedBox(width: 8),
                            Expanded(
                                child: _text(_dns2, 'DNS 2', onChanged: _markDirty)),
                          ],
                        ),
                        _multiline(_dnsRulesList, label: 'DNS 规则列表',
                            onChanged: _markDirty),
                        Row(
                          children: [
                            Expanded(
                              child: _text(_dnsDomestic, '国内 DNS',
                                  onChanged: _markDirty),
                            ),
                            const SizedBox(width: 8),
                            Expanded(
                              child: _text(_dnsForeign, '国外 DNS',
                                  onChanged: _markDirty),
                            ),
                          ],
                        ),
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          value: _dnsFakeIpEnabled,
                          title: const Text('Fake-IP'),
                          subtitle: const Text('Clash 风格即时假 IP，后台解析真实地址'),
                          onChanged: (v) => setState(() {
                            _dnsFakeIpEnabled = v;
                            _markDirty();
                          }),
                        ),
                        if (_dnsFakeIpEnabled)
                          _text(_dnsFakeIpRange, 'Fake-IP 地址池 (CIDR)',
                              onChanged: _markDirty),
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          value: _dnsEcsEnabled,
                          title: const Text('ECS (EDNS Client Subnet)'),
                          onChanged: (v) => setState(() {
                            _dnsEcsEnabled = v;
                            _markDirty();
                          }),
                        ),
                        if (_dnsEcsEnabled)
                          _text(_dnsEcsOverride, 'ECS Override IP (可选)',
                              onChanged: _markDirty),
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          value: _dnsTlsVerifyPeer,
                          title: const Text('TLS 校验'),
                          onChanged: (v) => setState(() {
                            _dnsTlsVerifyPeer = v;
                            _markDirty();
                          }),
                        ),
                        _multiline(_dnsStunCandidates, label: 'STUN 候选',
                            onChanged: _markDirty, height: 100),
                      ],
                    ),
                    const SizedBox(height: 12),
                    AppSectionCard(
                      title: 'Geo / Bypass',
                      icon: Icons.public_rounded,
                      tint: Colors.orange,
                      children: [
                        Text('路由模式', style: theme.textTheme.bodyMedium),
                        const SizedBox(height: 6),
                        SegmentedButton<LaunchRouteMode>(
                          showSelectedIcon: false,
                          segments: [
                            for (final mode in LaunchRouteMode.values)
                              ButtonSegment(
                                value: mode,
                                label: Text(mode.label),
                              ),
                          ],
                          selected: {_routeMode},
                          onSelectionChanged: (s) {
                            if (s.isEmpty) return;
                            setState(() {
                              _routeMode = s.first;
                              _markDirty();
                            });
                          },
                        ),
                        const SizedBox(height: 8),
                        _text(_geoCountry, 'Geo Country (如 cn)',
                            onChanged: _markDirty),
                        Row(
                          children: [
                            Expanded(
                              child: _text(_geoIpDat, 'GeoIP.dat',
                                  onChanged: _markDirty),
                            ),
                            const SizedBox(width: 8),
                            Expanded(
                              child: _text(_geoSiteDat, 'GeoSite.dat',
                                  onChanged: _markDirty),
                            ),
                          ],
                        ),
                        _multiline(_bypassIpList,
                            label: 'Bypass IP / CIDR', onChanged: _markDirty),
                      ],
                    ),
                    const SizedBox(height: 12),
                    AppSectionCard(
                      title: 'TUN 接口',
                      icon: Icons.lan_outlined,
                      tint: Colors.teal,
                      children: [
                        Row(
                          children: [
                            Expanded(
                                child: _text(_tunIp, 'TUN IP', onChanged: _markDirty)),
                            const SizedBox(width: 8),
                            Expanded(
                                child:
                                    _text(_tunMask, 'TUN Mask', onChanged: _markDirty)),
                          ],
                        ),
                        Row(
                          children: [
                            Expanded(
                              child: _text(_tunPrefix, 'TUN Prefix',
                                  keyboardType: TextInputType.number,
                                  onChanged: _markDirty),
                            ),
                            const SizedBox(width: 8),
                            Expanded(
                                child:
                                    _text(_gateway, 'Gateway', onChanged: _markDirty)),
                          ],
                        ),
                        _text(_mtu, 'MTU',
                            keyboardType: TextInputType.number, onChanged: _markDirty),
                        Row(
                          children: [
                            Expanded(
                                child: _text(_route, 'Route', onChanged: _markDirty)),
                            const SizedBox(width: 8),
                            Expanded(
                              child: _text(_routePrefix, 'Route Prefix',
                                  keyboardType: TextInputType.number,
                                  onChanged: _markDirty),
                            ),
                          ],
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    Card(
                      child: ListTile(
                        leading: const Icon(Icons.tune_rounded),
                        title: const Text('高级参数'),
                        subtitle: const Text('VNet、Block QUIC、分应用代理、Geo 规则生成器等'),
                        trailing: const Icon(Icons.chevron_right_rounded),
                        onTap: () async {
                          if (_dirty) await _save(showSnack: false);
                          if (!mounted) return;
                          await Navigator.of(context).push(
                            MaterialPageRoute(
                              builder: (_) => const OptionsAdvancedPage(),
                            ),
                          );
                          await _load();
                        },
                      ),
                    ),
                    const SizedBox(height: 12),
                    FilledButton.tonal(
                      style: FilledButton.styleFrom(
                        foregroundColor: theme.colorScheme.error,
                      ),
                      onPressed: _reset,
                      child: const Text('恢复默认'),
                    ),
                    const SizedBox(height: 8),
                    FilledButton.icon(
                      onPressed: _dirty ? _save : null,
                      icon: const Icon(Icons.save_rounded),
                      label: Text(_dirty ? '保存到「${_profile!.name}」' : '已保存'),
                    ),
                  ],
                ),
    );
  }

  Widget _activeBanner(ThemeData theme) {
    final p = _profile!;
    final ep = p.serverEndpoint ?? '';
    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: theme.colorScheme.primaryContainer.withValues(alpha: 0.4),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: theme.colorScheme.outlineVariant),
      ),
      child: Row(
        children: [
          Icon(Icons.bookmark_rounded, color: theme.colorScheme.primary),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  '当前编辑: ${p.name}',
                  style: theme.textTheme.titleSmall
                      ?.copyWith(fontWeight: FontWeight.w800),
                ),
                if (ep.isNotEmpty)
                  Text(
                    ep,
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                  ),
              ],
            ),
          ),
          Text(
            _dirty ? '未保存' : '已同步',
            style: theme.textTheme.bodySmall?.copyWith(
              color: _dirty
                  ? theme.colorScheme.error
                  : theme.colorScheme.primary,
              fontWeight: FontWeight.w700,
            ),
          ),
        ],
      ),
    );
  }

  Widget _text(
    TextEditingController c,
    String label, {
    TextInputType? keyboardType,
    VoidCallback? onChanged,
  }) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: TextField(
        controller: c,
        keyboardType: keyboardType,
        onChanged: onChanged == null ? null : (_) => onChanged(),
        decoration: InputDecoration(
          labelText: label,
          border: const OutlineInputBorder(),
          isDense: true,
        ),
      ),
    );
  }

  Widget _multiline(
    TextEditingController c, {
    required String label,
    VoidCallback? onChanged,
    double height = 120,
  }) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label, style: Theme.of(context).textTheme.bodySmall),
          const SizedBox(height: 6),
          SizedBox(
            height: height,
            child: TextField(
              controller: c,
              maxLines: null,
              expands: true,
              textAlignVertical: TextAlignVertical.top,
              onChanged: onChanged == null ? null : (_) => onChanged(),
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              decoration: const InputDecoration(
                border: OutlineInputBorder(),
                contentPadding: EdgeInsets.all(12),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
