import 'package:flutter/material.dart';
import '../models/config_profile.dart';
import '../services/profile_store.dart';
import '../utils/profile_groups.dart';
import '../widgets/profile_ui.dart';
import 'profile_edit_page.dart';

class SelectProfilePage extends StatefulWidget {
  const SelectProfilePage({super.key});

  @override
  State<SelectProfilePage> createState() => _SelectProfilePageState();
}

class _SelectProfilePageState extends State<SelectProfilePage> {
  final _store = ProfileStore();
  final _searchController = TextEditingController();
  List<ConfigProfile> _profiles = const [];
  String? _activeId;
  bool _loading = true;
  String _query = '';

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final profiles = await _store.getProfiles();
    final active = await _store.getActive();
    if (!mounted) return;
    setState(() {
      _profiles = profiles;
      _activeId = active?.id;
      _loading = false;
    });
  }

  Future<void> _select(ConfigProfile p) async {
    await _store.setActive(p.id);
    if (!mounted) return;
    Navigator.of(context).pop(p.id);
  }

  Future<void> _togglePin(ConfigProfile p) async {
    await _store.toggleFavorite(p.id);
    await _load();
  }

  Future<void> _add() async {
    final created = await Navigator.of(context).push<bool>(
      MaterialPageRoute(builder: (_) => const ProfileEditPage()),
    );
    if (created == true) await _load();
  }

  List<ConfigProfile> get _filtered {
    if (_query.isEmpty) return _profiles;
    final q = _query.toLowerCase();
    return _profiles.where((p) {
      return p.name.toLowerCase().contains(q) ||
          p.subtitle.toLowerCase().contains(q) ||
          (p.serverEndpoint ?? '').toLowerCase().contains(q);
    }).toList();
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final groups = ProfileGroups.fromProfiles(_filtered);

    return Scaffold(
      appBar: AppBar(
        title: const Text('选择节点'),
        centerTitle: true,
        actions: [
          IconButton(
            icon: const Icon(Icons.add_rounded),
            tooltip: '新增配置',
            onPressed: _add,
          ),
        ],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : Column(
              children: [
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 8, 16, 8),
                  child: TextField(
                    controller: _searchController,
                    onChanged: (v) => setState(() => _query = v),
                    decoration: InputDecoration(
                      hintText: '搜索配置名称或地址...',
                      prefixIcon: const Icon(Icons.search_rounded),
                      filled: true,
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(14),
                        borderSide: BorderSide.none,
                      ),
                      contentPadding: const EdgeInsets.symmetric(vertical: 0),
                    ),
                  ),
                ),
                Expanded(
                  child: groups.isEmpty
                      ? Center(
                          child: Text(
                            '没有匹配的配置',
                            style: theme.textTheme.bodyMedium?.copyWith(
                              color: theme.colorScheme.onSurfaceVariant,
                            ),
                          ),
                        )
                      : GroupedProfileList(
                          profiles: _filtered,
                          activeId: _activeId,
                          onTap: _select,
                          onApply: _select,
                          onTogglePin: _togglePin,
                        ),
                ),
              ],
            ),
    );
  }
}
