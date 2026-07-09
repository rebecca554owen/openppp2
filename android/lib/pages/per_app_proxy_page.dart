import 'dart:convert';

import 'package:flutter/material.dart';

import '../models/config_profile.dart';
import '../services/profile_store.dart';
import '../vpn_service.dart';

/// Per-app proxy editor.
///
/// Reads/writes `options.perAppProxyEnabled`, `options.perAppProxyMode`
/// (`'allow'` | `'deny'`), and `options.perAppProxyApps` (list of package
/// names) on the *active* profile. Auto-append (system-wide) is configured
/// from the launch options page; this screen focuses on the package list.
class PerAppProxyPage extends StatefulWidget {
  const PerAppProxyPage({super.key});

  @override
  State<PerAppProxyPage> createState() => _PerAppProxyPageState();
}

class _AppEntry {
  final String package;
  final String label;
  final bool system;
  _AppEntry({required this.package, required this.label, required this.system});
}

class _PerAppProxyPageState extends State<PerAppProxyPage> {
  final _store = ProfileStore();
  final _vpn = VpnService();
  final _searchController = TextEditingController();
  final _iconCache = <String, String>{}; // package -> base64 PNG

  ConfigProfile? _profile;
  List<_AppEntry> _allApps = const [];
  Set<String> _selected = <String>{};
  bool _enabled = false;
  String _mode = 'allow';
  bool _includeSystem = false;
  String _query = '';
  bool _loading = true;
  bool _dirty = false;

  @override
  void initState() {
    super.initState();
    _searchController.addListener(() {
      setState(() => _query = _searchController.text.trim().toLowerCase());
    });
    _load();
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
    final options = await _store.getProfileOptions(active.id);
    final enabled = options['perAppProxyEnabled'] == true;
    final mode = (options['perAppProxyMode'] ?? 'allow').toString();
    final raw = options['perAppProxyApps'];
    final selected = <String>{};
    if (raw is List) {
      for (final v in raw) {
        if (v is String && v.isNotEmpty) selected.add(v);
      }
    }
    final apps = await _vpn.getInstalledApps(includeSystem: _includeSystem);
    if (!mounted) return;
    setState(() {
      _profile = active;
      _enabled = enabled;
      _mode = mode == 'deny' ? 'deny' : 'allow';
      _selected = selected;
      _allApps = apps
          .map((m) => _AppEntry(
                package: (m['package'] ?? '').toString(),
                label: (m['label'] ?? '').toString(),
                system: m['system'] == true,
              ))
          .where((a) => a.package.isNotEmpty)
          .toList(growable: false);
      _loading = false;
    });
  }

  Future<void> _reloadAppList() async {
    setState(() => _loading = true);
    final apps = await _vpn.getInstalledApps(includeSystem: _includeSystem);
    if (!mounted) return;
    setState(() {
      _allApps = apps
          .map((m) => _AppEntry(
                package: (m['package'] ?? '').toString(),
                label: (m['label'] ?? '').toString(),
                system: m['system'] == true,
              ))
          .where((a) => a.package.isNotEmpty)
          .toList(growable: false);
      _loading = false;
    });
  }

  List<_AppEntry> get _filtered {
    if (_query.isEmpty) return _allApps;
    return _allApps
        .where((a) =>
            a.label.toLowerCase().contains(_query) ||
            a.package.toLowerCase().contains(_query))
        .toList(growable: false);
  }

  void _markDirty() {
    if (!_dirty) setState(() => _dirty = true);
  }

  Future<String?> _iconFor(String package) async {
    final cached = _iconCache[package];
    if (cached != null) return cached;
    final v = await _vpn.getAppIcon(package);
    if (v != null) _iconCache[package] = v;
    return v;
  }

  Future<void> _save({bool showSnack = true}) async {
    final p = _profile;
    if (p == null) return;
    final options = await _store.getProfileOptions(p.id);
    options['perAppProxyEnabled'] = _enabled;
    options['perAppProxyMode'] = _mode;
    options['perAppProxyApps'] = _selected.toList()..sort();
    await _store.setProfileOptions(p.id, options);
    if (!mounted) return;
    setState(() => _dirty = false);
    if (showSnack) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('已保存到「${p.name}」（${_selected.length} 个应用）')),
      );
    }
  }

  Future<bool> _confirmDiscard() async {
    if (!_dirty) return true;
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('未保存'),
        content: const Text('返回前是否保存修改？'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(null),
            child: const Text('取消'),
          ),
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('放弃'),
          ),
          FilledButton.tonal(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('保存'),
          ),
        ],
      ),
    );
    if (ok == null) return false;
    if (ok) await _save(showSnack: false);
    return true;
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final filtered = _filtered;
    final allFilteredSelected =
        filtered.isNotEmpty && filtered.every((a) => _selected.contains(a.package));
    return PopScope(
      canPop: !_dirty,
      onPopInvokedWithResult: (didPop, _) async {
        if (didPop) return;
        if (await _confirmDiscard() && mounted) {
          Navigator.of(context).pop();
        }
      },
      child: Scaffold(
        appBar: AppBar(
          title: const Text('分应用代理'),
          centerTitle: true,
          actions: [
            IconButton(
              tooltip: allFilteredSelected ? '取消全选' : '全选',
              icon: Icon(allFilteredSelected
                  ? Icons.deselect_rounded
                  : Icons.select_all_rounded),
              onPressed: _enabled && filtered.isNotEmpty
                  ? () {
                      setState(() {
                        if (allFilteredSelected) {
                          _selected.removeAll(filtered.map((a) => a.package));
                        } else {
                          _selected.addAll(filtered.map((a) => a.package));
                        }
                        _markDirty();
                      });
                    }
                  : null,
            ),
            IconButton(
              tooltip: '保存',
              icon: const Icon(Icons.save_rounded),
              onPressed: _profile == null || !_dirty ? null : () => _save(),
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
                : Column(
                    children: [
                      _Header(
                        profileName: _profile!.name,
                        enabled: _enabled,
                        mode: _mode,
                        selectedCount: _selected.length,
                        totalCount: _allApps.length,
                        includeSystem: _includeSystem,
                        searchController: _searchController,
                        onEnabledChanged: (v) {
                          setState(() {
                            _enabled = v;
                            _markDirty();
                          });
                        },
                        onModeChanged: (m) {
                          setState(() {
                            _mode = m;
                            _markDirty();
                          });
                        },
                        onIncludeSystemChanged: (v) async {
                          setState(() => _includeSystem = v);
                          await _reloadAppList();
                        },
                      ),
                      const Divider(height: 1),
                      Expanded(
                        child: filtered.isEmpty
                            ? Center(
                                child: Text(
                                  _query.isEmpty
                                      ? '没有可代理的应用'
                                      : '无匹配的应用',
                                  style: theme.textTheme.bodyMedium,
                                ),
                              )
                            : ListView.builder(
                                itemCount: filtered.length,
                                itemBuilder: (ctx, i) {
                                  final app = filtered[i];
                                  final checked =
                                      _selected.contains(app.package);
                                  return _AppTile(
                                    label: app.label,
                                    package: app.package,
                                    system: app.system,
                                    checked: checked,
                                    enabled: _enabled,
                                    iconLoader: () => _iconFor(app.package),
                                    onToggle: (v) {
                                      setState(() {
                                        if (v) {
                                          _selected.add(app.package);
                                        } else {
                                          _selected.remove(app.package);
                                        }
                                        _markDirty();
                                      });
                                    },
                                  );
                                },
                              ),
                      ),
                    ],
                  ),
      ),
    );
  }
}

class _Header extends StatelessWidget {
  final String profileName;
  final bool enabled;
  final String mode;
  final int selectedCount;
  final int totalCount;
  final bool includeSystem;
  final TextEditingController searchController;
  final ValueChanged<bool> onEnabledChanged;
  final ValueChanged<String> onModeChanged;
  final ValueChanged<bool> onIncludeSystemChanged;

  const _Header({
    required this.profileName,
    required this.enabled,
    required this.mode,
    required this.selectedCount,
    required this.totalCount,
    required this.includeSystem,
    required this.searchController,
    required this.onEnabledChanged,
    required this.onModeChanged,
    required this.onIncludeSystemChanged,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      '当前编辑: $profileName',
                      style: theme.textTheme.titleSmall
                          ?.copyWith(fontWeight: FontWeight.w800),
                    ),
                    Text(
                      '已选 $selectedCount / $totalCount',
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ],
                ),
              ),
              Switch(
                value: enabled,
                onChanged: onEnabledChanged,
              ),
            ],
          ),
          const SizedBox(height: 8),
          Opacity(
            opacity: enabled ? 1 : 0.5,
            child: SegmentedButton<String>(
              segments: const [
                ButtonSegment(
                  value: 'allow',
                  label: Text('仅代理选中'),
                  icon: Icon(Icons.shield_rounded),
                ),
                ButtonSegment(
                  value: 'deny',
                  label: Text('排除选中'),
                  icon: Icon(Icons.block_rounded),
                ),
              ],
              selected: {mode},
              onSelectionChanged: enabled
                  ? (s) => onModeChanged(s.first)
                  : null,
            ),
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: searchController,
                  decoration: InputDecoration(
                    isDense: true,
                    prefixIcon: const Icon(Icons.search_rounded, size: 20),
                    hintText: '搜索应用名 / 包名',
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(10),
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              FilterChip(
                selected: includeSystem,
                label: const Text('含系统'),
                onSelected: onIncludeSystemChanged,
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _AppTile extends StatefulWidget {
  final String label;
  final String package;
  final bool system;
  final bool checked;
  final bool enabled;
  final Future<String?> Function() iconLoader;
  final ValueChanged<bool> onToggle;

  const _AppTile({
    required this.label,
    required this.package,
    required this.system,
    required this.checked,
    required this.enabled,
    required this.iconLoader,
    required this.onToggle,
  });

  @override
  State<_AppTile> createState() => _AppTileState();
}

class _AppTileState extends State<_AppTile> {
  String? _iconBase64;
  bool _loadingIcon = false;

  @override
  void initState() {
    super.initState();
    _loadIcon();
  }

  Future<void> _loadIcon() async {
    if (_loadingIcon) return;
    _loadingIcon = true;
    final v = await widget.iconLoader();
    if (!mounted) return;
    setState(() => _iconBase64 = v);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    Widget leading;
    if (_iconBase64 != null && _iconBase64!.isNotEmpty) {
      leading = ClipRRect(
        borderRadius: BorderRadius.circular(8),
        child: Image.memory(
          base64Decode(_iconBase64!),
          width: 36,
          height: 36,
          fit: BoxFit.cover,
          gaplessPlayback: true,
        ),
      );
    } else {
      leading = Container(
        width: 36,
        height: 36,
        decoration: BoxDecoration(
          color: theme.colorScheme.primary.withValues(alpha: 0.15),
          borderRadius: BorderRadius.circular(8),
        ),
        alignment: Alignment.center,
        child: Text(
          widget.label.isNotEmpty ? widget.label.characters.first : '?',
          style: TextStyle(
            color: theme.colorScheme.primary,
            fontWeight: FontWeight.w800,
          ),
        ),
      );
    }
    return Opacity(
      opacity: widget.enabled ? 1 : 0.55,
      child: CheckboxListTile(
        value: widget.checked,
        onChanged: widget.enabled
            ? (v) => widget.onToggle(v ?? false)
            : null,
        controlAffinity: ListTileControlAffinity.trailing,
        secondary: leading,
        title: Text(
          widget.label,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
        ),
        subtitle: Text(
          widget.system ? '${widget.package} · 系统' : widget.package,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: theme.textTheme.bodySmall?.copyWith(
            color: theme.colorScheme.onSurfaceVariant,
          ),
        ),
        dense: true,
      ),
    );
  }
}
