import 'dart:async';
import 'package:flutter/material.dart';
import '../models/config_profile.dart';
import '../services/profile_store.dart';
import 'per_app_proxy_page.dart';

/// Per-profile VPN startup options.
///
/// Layout: sectioned form cards (TUN / 路由 / DNS / Geo Bypass / 高级).
/// Each Profile carries its own copy of these options; switching the active
/// profile reloads this page automatically.
class OptionsPage extends StatefulWidget {
  const OptionsPage({super.key});

  @override
  State<OptionsPage> createState() => _OptionsPageState();
}

class _OptionsPageState extends State<OptionsPage> {
  final _store = ProfileStore();

  // TUN
  final _tunIp = TextEditingController();
  final _tunMask = TextEditingController();
  final _tunPrefix = TextEditingController();
  final _gateway = TextEditingController();
  final _mtu = TextEditingController();

  // Route
  final _route = TextEditingController();
  final _routePrefix = TextEditingController();

  // DNS
  final _dns1 = TextEditingController();
  final _dns2 = TextEditingController();
  final _dnsRulesList = TextEditingController();

  // Geo bypass (CIDR list)
  final _bypassIpList = TextEditingController();

  // Advanced
  final _mark = TextEditingController();
  final _mux = TextEditingController();
  bool _vnet = false;
  bool _blockQuic = false;
  bool _staticMode = false;

  // DNS resolver (AppConfiguration.dns block)
  final _dnsDomestic = TextEditingController();
  final _dnsForeign = TextEditingController();
  final _dnsEcsOverride = TextEditingController();
  final _dnsStunCandidates = TextEditingController();
  bool _dnsInterceptUnmatched = true;
  bool _dnsEcsEnabled = true;
  bool _dnsTlsVerifyPeer = true;

  // Geo rules (AppConfiguration.geo-rules block)
  final _geoCountry = TextEditingController();
  final _geoIpDat = TextEditingController();
  final _geoSiteDat = TextEditingController();
  final _geoIpDownloadUrl = TextEditingController();
  final _geoSiteDownloadUrl = TextEditingController();
  final _geoIpFiles = TextEditingController();
  final _geoSiteFiles = TextEditingController();
  final _geoDnsProviderDomestic = TextEditingController();
  final _geoDnsProviderForeign = TextEditingController();
  final _geoOutputBypass = TextEditingController();
  final _geoOutputDnsRules = TextEditingController();
  bool _geoEnabled = true;

  // Proxy (per-app + LAN + auto-append)
  bool _perAppProxyEnabled = false;
  String _perAppProxyMode = 'allow';
  List<String> _perAppProxyApps = const <String>[];
  bool _autoAppendApps = false;
  bool _allowLan = true;

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
    final active = await _store.getActive();
    if (active == null) return;
    if (_profile?.id != active.id) {
      await _load();
    }
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
    _mark.text = (m['mark'] ?? '0').toString();
    _mux.text = (m['mux'] ?? '0').toString();
    _bypassIpList.text = (m['bypassIpList'] ?? '').toString();
    _dnsRulesList.text = (m['dnsRulesList'] ?? '').toString();
    _vnet = m['vnet'] == true;
    _blockQuic = m['blockQuic'] == true;
    _staticMode = m['staticMode'] == true;

    final dnsCfg = (m['dnsConfig'] is Map)
        ? Map<String, dynamic>.from(m['dnsConfig'] as Map)
        : <String, dynamic>{};
    _dnsDomestic.text = (dnsCfg['domestic'] ?? '').toString();
    _dnsForeign.text = (dnsCfg['foreign'] ?? '').toString();
    _dnsEcsOverride.text = (dnsCfg['ecsOverrideIp'] ?? '').toString();
    _dnsStunCandidates.text = (dnsCfg['stunCandidates'] ?? '').toString();
    _dnsInterceptUnmatched = dnsCfg['interceptUnmatched'] == true;
    _dnsEcsEnabled = dnsCfg['ecsEnabled'] == true;
    _dnsTlsVerifyPeer = dnsCfg['tlsVerifyPeer'] == true;

    final geo = (m['geoRules'] is Map)
        ? Map<String, dynamic>.from(m['geoRules'] as Map)
        : <String, dynamic>{};
    _geoEnabled = geo['enabled'] == true;
    _geoCountry.text = (geo['country'] ?? '').toString();
    _geoIpDat.text = (geo['geoipDat'] ?? '').toString();
    _geoSiteDat.text = (geo['geositeDat'] ?? '').toString();
    _geoIpDownloadUrl.text = (geo['geoipDownloadUrl'] ?? '').toString();
    _geoSiteDownloadUrl.text = (geo['geositeDownloadUrl'] ?? '').toString();
    _geoIpFiles.text = (geo['geoipFiles'] ?? '').toString();
    _geoSiteFiles.text = (geo['geositeFiles'] ?? '').toString();
    _geoDnsProviderDomestic.text =
        (geo['dnsProviderDomestic'] ?? '').toString();
    _geoDnsProviderForeign.text =
        (geo['dnsProviderForeign'] ?? '').toString();
    _geoOutputBypass.text = (geo['outputBypass'] ?? '').toString();
    _geoOutputDnsRules.text = (geo['outputDnsRules'] ?? '').toString();

    _perAppProxyEnabled = m['perAppProxyEnabled'] == true;
    final mode = (m['perAppProxyMode'] ?? 'allow').toString();
    _perAppProxyMode = mode == 'deny' ? 'deny' : 'allow';
    final apps = m['perAppProxyApps'];
    _perAppProxyApps = (apps is List)
        ? apps.whereType<String>().where((s) => s.isNotEmpty).toList()
        : const <String>[];
    _autoAppendApps = m['autoAppendApps'] == true;
    _allowLan = m['allowLan'] == true;
  }

  Map<String, dynamic> _readForm() => {
        'tunIp': _tunIp.text.trim(),
        'tunMask': _tunMask.text.trim(),
        'tunPrefix': int.tryParse(_tunPrefix.text.trim()) ?? 24,
        'gateway': _gateway.text.trim(),
        'route': _route.text.trim(),
        'routePrefix': int.tryParse(_routePrefix.text.trim()) ?? 0,
        'dns1': _dns1.text.trim(),
        'dns2': _dns2.text.trim(),
        'mtu': int.tryParse(_mtu.text.trim()) ?? 1400,
        'mark': int.tryParse(_mark.text.trim()) ?? 0,
        'mux': int.tryParse(_mux.text.trim()) ?? 0,
        'vnet': _vnet,
        'blockQuic': _blockQuic,
        'staticMode': _staticMode,
        'bypassIpList': _bypassIpList.text,
        'dnsRulesList': _dnsRulesList.text,
        'dnsConfig': {
          'domestic': _dnsDomestic.text.trim(),
          'foreign': _dnsForeign.text.trim(),
          'interceptUnmatched': _dnsInterceptUnmatched,
          'ecsEnabled': _dnsEcsEnabled,
          'ecsOverrideIp': _dnsEcsOverride.text.trim(),
          'tlsVerifyPeer': _dnsTlsVerifyPeer,
          'stunCandidates': _dnsStunCandidates.text,
        },
        'geoRules': {
          'enabled': _geoEnabled,
          'country': _geoCountry.text.trim(),
          'geoipDat': _geoIpDat.text.trim(),
          'geositeDat': _geoSiteDat.text.trim(),
          'geoipDownloadUrl': _geoIpDownloadUrl.text.trim(),
          'geositeDownloadUrl': _geoSiteDownloadUrl.text.trim(),
          'geoipFiles': _geoIpFiles.text,
          'geositeFiles': _geoSiteFiles.text,
          'dnsProviderDomestic': _geoDnsProviderDomestic.text.trim(),
          'dnsProviderForeign': _geoDnsProviderForeign.text.trim(),
          'outputBypass': _geoOutputBypass.text.trim(),
          'outputDnsRules': _geoOutputDnsRules.text.trim(),
        },
        'perAppProxyEnabled': _perAppProxyEnabled,
        'perAppProxyMode': _perAppProxyMode,
        'perAppProxyApps': List<String>.from(_perAppProxyApps),
        'autoAppendApps': _autoAppendApps,
        'allowLan': _allowLan,
      };

  void _markDirty() {
    if (!_dirty) setState(() => _dirty = true);
  }

  String _perAppProxySubtitle() {
    if (!_perAppProxyEnabled) return '未启用 · 全部应用走 VPN';
    final n = _perAppProxyApps.length;
    final modeLabel = _perAppProxyMode == 'deny' ? '排除选中' : '仅代理选中';
    return '$modeLabel · 已选 $n 个应用';
  }

  Future<void> _openPerAppProxyPage() async {
    // Persist any pending edits before navigating, since the picker reads
    // straight from ProfileStore and would otherwise overwrite the dirty
    // toggle/mode the user just changed.
    if (_dirty) {
      await _save(showSnack: false);
    }
    if (!mounted) return;
    await Navigator.of(context).push(
      MaterialPageRoute(builder: (_) => const PerAppProxyPage()),
    );
    // Refresh state after returning -- the picker may have changed enabled,
    // mode, or the package list.
    if (!mounted) return;
    final p = _profile;
    if (p != null) {
      final fresh = await _store.getProfileOptions(p.id);
      if (!mounted) return;
      setState(() {
        _perAppProxyEnabled = fresh['perAppProxyEnabled'] == true;
        final mode = (fresh['perAppProxyMode'] ?? 'allow').toString();
        _perAppProxyMode = mode == 'deny' ? 'deny' : 'allow';
        final apps = fresh['perAppProxyApps'];
        _perAppProxyApps = (apps is List)
            ? apps.whereType<String>().where((s) => s.isNotEmpty).toList()
            : const <String>[];
      });
    }
  }

  Future<void> _save({bool showSnack = true}) async {
    final p = _profile;
    if (p == null) return;
    final m = _readForm();
    await _store.setProfileOptions(p.id, m);
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
        content: Text(
          '将「${_profile?.name ?? '当前配置'}」的启动参数恢复为默认值？',
        ),
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

  Future<void> _copyToAll() async {
    final p = _profile;
    if (p == null) return;
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('应用到所有配置文件'),
        content: const Text(
          '将当前表单中的启动参数（DNS / Geo / TUN / 路由）应用到所有配置文件？',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('取消'),
          ),
          FilledButton.tonal(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('应用全部'),
          ),
        ],
      ),
    );
    if (ok != true) return;
    final m = _readForm();
    final list = await _store.getProfiles();
    for (final it in list) {
      await _store.setProfileOptions(it.id, m);
    }
    if (!mounted) return;
    setState(() => _dirty = false);
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('已应用到 ${list.length} 个配置文件')),
    );
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
      _mark,
      _mux,
      _bypassIpList,
      _dnsRulesList,
      _dnsDomestic,
      _dnsForeign,
      _dnsEcsOverride,
      _dnsStunCandidates,
      _geoCountry,
      _geoIpDat,
      _geoSiteDat,
      _geoIpDownloadUrl,
      _geoSiteDownloadUrl,
      _geoIpFiles,
      _geoSiteFiles,
      _geoDnsProviderDomestic,
      _geoDnsProviderForeign,
      _geoOutputBypass,
      _geoOutputDnsRules,
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
            tooltip: '应用到所有配置文件',
            icon: const Icon(Icons.copy_all_rounded),
            onPressed: _profile == null ? null : _copyToAll,
          ),
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
                    _Section(
                      title: '代理',
                      icon: Icons.account_tree_rounded,
                      tint: Colors.cyan,
                      children: [
                        ListTile(
                          contentPadding: EdgeInsets.zero,
                          leading: const Icon(Icons.apps_rounded),
                          title: const Text('分应用代理'),
                          subtitle: Text(_perAppProxySubtitle()),
                          trailing: const Icon(Icons.chevron_right_rounded),
                          onTap: _openPerAppProxyPage,
                        ),
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          value: _allowLan,
                          title: const Text('允许局域网代理'),
                          subtitle: const Text(
                              '本机 HTTP / SOCKS5 代理监听 0.0.0.0，供 LAN 设备使用'),
                          onChanged: (v) => setState(() {
                            _allowLan = v;
                            _markDirty();
                          }),
                        ),
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          value: _autoAppendApps,
                          title: const Text('系统 HTTP 代理'),
                          subtitle: const Text(
                              '把本机 HTTP 代理(127.0.0.1)注入为系统级代理 · 需 Android 10+'),
                          onChanged: (v) => setState(() {
                            _autoAppendApps = v;
                            _markDirty();
                          }),
                        ),
                      ],
                    ),
                    _Section(
                      title: 'DNS',
                      icon: Icons.dns_rounded,
                      tint: theme.colorScheme.primary,
                      children: [
                        Row(
                          children: [
                            Expanded(child: _text(_dns1, 'DNS 1', onChanged: _markDirty)),
                            const SizedBox(width: 8),
                            Expanded(child: _text(_dns2, 'DNS 2', onChanged: _markDirty)),
                          ],
                        ),
                        const SizedBox(height: 4),
                        Text('DNS 规则列表（每行一条）', style: theme.textTheme.bodySmall),
                        const SizedBox(height: 6),
                        _multiline(
                          _dnsRulesList,
                          hint: '8.8.8.8\n1.1.1.1\nexample.com=1.1.1.1',
                          onChanged: _markDirty,
                        ),
                      ],
                    ),
                    _Section(
                      title: 'Geo / Bypass IP',
                      icon: Icons.public_rounded,
                      tint: Colors.orange,
                      children: [
                        Text(
                          '直连不走 VPN 的网段（CIDR / IP，每行一条）',
                          style: theme.textTheme.bodySmall,
                        ),
                        const SizedBox(height: 6),
                        _multiline(
                          _bypassIpList,
                          hint: '192.168.0.0/16\n10.0.0.0/8\n172.16.0.0/12',
                          onChanged: _markDirty,
                        ),
                      ],
                    ),
                    _Section(
                      title: 'DNS 解析 (AppConfiguration)',
                      icon: Icons.translate_rounded,
                      tint: theme.colorScheme.tertiary,
                      children: [
                        Padding(
                          padding: const EdgeInsets.only(bottom: 8),
                          child: Text(
                            '注入到 client 配置 dns 段，启动时下发到引擎。',
                            style: theme.textTheme.bodySmall?.copyWith(
                              color: theme.colorScheme.onSurfaceVariant,
                            ),
                          ),
                        ),
                        Row(
                          children: [
                            Expanded(
                              child: _text(_dnsDomestic, '国内 DNS (domestic)',
                                  onChanged: _markDirty),
                            ),
                            const SizedBox(width: 8),
                            Expanded(
                              child: _text(_dnsForeign, '国外 DNS (foreign)',
                                  onChanged: _markDirty),
                            ),
                          ],
                        ),
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          value: _dnsInterceptUnmatched,
                          title: const Text('intercept-unmatched'),
                          subtitle: const Text(
                              '未匹配的 DNS 查询走 foreign 上游'),
                          onChanged: (v) => setState(() {
                            _dnsInterceptUnmatched = v;
                            _markDirty();
                          }),
                        ),
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          value: _dnsEcsEnabled,
                          title: const Text('ECS (EDNS Client Subnet)'),
                          subtitle: const Text(
                              '为 domestic 查询附带客户端子网信息'),
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
                          title: const Text('TLS 校验 (verify-peer)'),
                          subtitle: const Text('校验 DoH/DoT 上游证书'),
                          onChanged: (v) => setState(() {
                            _dnsTlsVerifyPeer = v;
                            _markDirty();
                          }),
                        ),
                        const SizedBox(height: 6),
                        Text('STUN 候选 (host:port，每行一条)',
                            style: theme.textTheme.bodySmall),
                        const SizedBox(height: 6),
                        _multiline(
                          _dnsStunCandidates,
                          hint:
                              '39.107.142.158:3478\n74.125.250.129:19302',
                          onChanged: _markDirty,
                        ),
                      ],
                    ),
                    _Section(
                      title: 'Geo 规则 (geo-rules)',
                      icon: Icons.travel_explore_rounded,
                      tint: Colors.deepOrange,
                      children: [
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          value: _geoEnabled,
                          title: const Text('启用 GeoIP / GeoSite 规则生成'),
                          subtitle: const Text(
                              '基于 dat / 文本规则生成 bypass + dns-rules'),
                          onChanged: (v) => setState(() {
                            _geoEnabled = v;
                            _markDirty();
                          }),
                        ),
                        if (_geoEnabled) ...[
                          _text(_geoCountry, 'country (如 cn / hk / tw)',
                              onChanged: _markDirty),
                          Row(
                            children: [
                              Expanded(
                                child: _text(_geoIpDat, 'GeoIP.dat 路径',
                                    onChanged: _markDirty),
                              ),
                              const SizedBox(width: 8),
                              Expanded(
                                child: _text(_geoSiteDat, 'GeoSite.dat 路径',
                                    onChanged: _markDirty),
                              ),
                            ],
                          ),
                          _text(_geoIpDownloadUrl, 'GeoIP 下载 URL',
                              onChanged: _markDirty),
                          _text(_geoSiteDownloadUrl, 'GeoSite 下载 URL',
                              onChanged: _markDirty),
                          const SizedBox(height: 4),
                          Text('GeoIP 文本源（每行一条路径）',
                              style: theme.textTheme.bodySmall),
                          const SizedBox(height: 6),
                          _multiline(_geoIpFiles,
                              hint: './rules/geoip-cn.txt',
                              onChanged: _markDirty,
                              height: 90),
                          const SizedBox(height: 4),
                          Text('GeoSite 文本源（每行一条路径）',
                              style: theme.textTheme.bodySmall),
                          const SizedBox(height: 6),
                          _multiline(_geoSiteFiles,
                              hint: './rules/geosite-cn.txt',
                              onChanged: _markDirty,
                              height: 90),
                          Row(
                            children: [
                              Expanded(
                                child: _text(_geoDnsProviderDomestic,
                                    'dns-provider-domestic',
                                    onChanged: _markDirty),
                              ),
                              const SizedBox(width: 8),
                              Expanded(
                                child: _text(_geoDnsProviderForeign,
                                    'dns-provider-foreign',
                                    onChanged: _markDirty),
                              ),
                            ],
                          ),
                          _text(_geoOutputBypass, 'output-bypass 路径',
                              onChanged: _markDirty),
                          _text(_geoOutputDnsRules, 'output-dns-rules 路径',
                              onChanged: _markDirty),
                        ],
                      ],
                    ),
                    _Section(
                      title: 'TUN 接口',
                      icon: Icons.lan_outlined,
                      tint: Colors.teal,
                      children: [
                        Row(
                          children: [
                            Expanded(child: _text(_tunIp, 'TUN IP', onChanged: _markDirty)),
                            const SizedBox(width: 8),
                            Expanded(child: _text(_tunMask, 'TUN Mask', onChanged: _markDirty)),
                          ],
                        ),
                        Row(
                          children: [
                            Expanded(
                              child: _text(_tunPrefix, 'TUN Prefix',
                                  keyboardType: TextInputType.number, onChanged: _markDirty),
                            ),
                            const SizedBox(width: 8),
                            Expanded(child: _text(_gateway, 'Gateway', onChanged: _markDirty)),
                          ],
                        ),
                        _text(_mtu, 'MTU',
                            keyboardType: TextInputType.number, onChanged: _markDirty),
                      ],
                    ),
                    _Section(
                      title: '路由',
                      icon: Icons.alt_route_rounded,
                      tint: Colors.indigo,
                      children: [
                        Row(
                          children: [
                            Expanded(child: _text(_route, 'Route', onChanged: _markDirty)),
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
                    _Section(
                      title: '高级',
                      icon: Icons.tune_rounded,
                      tint: Colors.purple,
                      children: [
                        Row(
                          children: [
                            Expanded(
                              child: _text(_mark, 'Mark',
                                  keyboardType: TextInputType.number, onChanged: _markDirty),
                            ),
                            const SizedBox(width: 8),
                            Expanded(
                              child: _text(_mux, 'Mux',
                                  keyboardType: TextInputType.number, onChanged: _markDirty),
                            ),
                          ],
                        ),
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          value: _vnet,
                          title: const Text('VNet'),
                          subtitle: const Text('启用虚拟网卡 (VEthernet)'),
                          onChanged: (v) => setState(() {
                            _vnet = v;
                            _markDirty();
                          }),
                        ),
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          value: _blockQuic,
                          title: const Text('Block QUIC'),
                          subtitle: const Text('屏蔽 UDP/443 防止 QUIC 绕过'),
                          onChanged: (v) => setState(() {
                            _blockQuic = v;
                            _markDirty();
                          }),
                        ),
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          value: _staticMode,
                          title: const Text('Static Mode'),
                          subtitle: const Text('UDP 静态隧道模式'),
                          onChanged: (v) => setState(() {
                            _staticMode = v;
                            _markDirty();
                          }),
                        ),
                      ],
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
          Container(
            width: 36,
            height: 36,
            decoration: BoxDecoration(
              color: theme.colorScheme.primary.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(10),
            ),
            alignment: Alignment.center,
            child: Icon(Icons.bookmark_rounded, color: theme.colorScheme.primary, size: 20),
          ),
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
                  Text(ep,
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                      )),
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

  Widget _text(TextEditingController c, String label,
      {TextInputType? keyboardType, VoidCallback? onChanged}) {
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

  Widget _multiline(TextEditingController c,
      {String? hint, VoidCallback? onChanged, double height = 130}) {
    return SizedBox(
      height: height,
      child: TextField(
        controller: c,
        maxLines: null,
        expands: true,
        textAlignVertical: TextAlignVertical.top,
        onChanged: onChanged == null ? null : (_) => onChanged(),
        style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
        decoration: InputDecoration(
          border: OutlineInputBorder(borderRadius: BorderRadius.circular(8)),
          contentPadding: const EdgeInsets.all(12),
          hintText: hint,
        ),
      ),
    );
  }
}

class _Section extends StatelessWidget {
  final String title;
  final IconData icon;
  final Color tint;
  final List<Widget> children;
  const _Section({
    required this.title,
    required this.icon,
    required this.tint,
    required this.children,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Material(
        color: theme.colorScheme.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(14),
          side: BorderSide(color: theme.colorScheme.outlineVariant),
        ),
        child: Padding(
          padding: const EdgeInsets.fromLTRB(14, 12, 14, 4),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Row(
                children: [
                  Icon(icon, size: 18, color: tint),
                  const SizedBox(width: 8),
                  Text(
                    title,
                    style: theme.textTheme.titleSmall?.copyWith(
                      fontWeight: FontWeight.w800,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              ...children,
            ],
          ),
        ),
      ),
    );
  }
}

