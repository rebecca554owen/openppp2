import 'package:flutter/material.dart';
import '../models/config_profile.dart';
import '../services/profile_store.dart';
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

  Future<void> _toggleFav(ConfigProfile p) async {
    await _store.toggleFavorite(p.id);
    await _load();
  }

  Future<void> _add() async {
    final created = await Navigator.of(context).push<bool>(
      MaterialPageRoute(builder: (_) => const ProfileEditPage()),
    );
    if (created == true) await _load();
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final filtered = _query.isEmpty
        ? _profiles
        : _profiles
            .where((p) =>
                p.name.toLowerCase().contains(_query.toLowerCase()) ||
                p.subtitle.toLowerCase().contains(_query.toLowerCase()))
            .toList();
    final favorites = filtered.where((p) => p.favorite).toList();
    final others = filtered.where((p) => !p.favorite).toList();

    return Scaffold(
      appBar: AppBar(
        title: const Text('Select a Location'),
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
                  child: ListView(
                    padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
                    children: [
                      if (favorites.isNotEmpty) ...[
                        _SectionHeader('Favorites'),
                        ...favorites.map((p) => _ProfileTile(
                              profile: p,
                              isActive: p.id == _activeId,
                              onTap: () => _select(p),
                              onFav: () => _toggleFav(p),
                            )),
                        const SizedBox(height: 8),
                      ],
                      _SectionHeader('Locations'),
                      if (others.isEmpty && favorites.isEmpty)
                        Padding(
                          padding: const EdgeInsets.symmetric(vertical: 24),
                          child: Center(
                            child: Text(
                              '没有匹配的配置',
                              style: theme.textTheme.bodyMedium?.copyWith(
                                color: theme.colorScheme.onSurfaceVariant,
                              ),
                            ),
                          ),
                        ),
                      ...others.map((p) => _ProfileTile(
                            profile: p,
                            isActive: p.id == _activeId,
                            onTap: () => _select(p),
                            onFav: () => _toggleFav(p),
                          )),
                    ],
                  ),
                ),
              ],
            ),
    );
  }
}

class _SectionHeader extends StatelessWidget {
  final String text;
  const _SectionHeader(this.text);
  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.fromLTRB(4, 12, 4, 8),
      child: Text(
        text,
        style: theme.textTheme.bodySmall?.copyWith(
          color: theme.colorScheme.onSurfaceVariant,
          letterSpacing: 1.0,
        ),
      ),
    );
  }
}

class _ProfileTile extends StatelessWidget {
  final ConfigProfile profile;
  final bool isActive;
  final VoidCallback onTap;
  final VoidCallback onFav;

  const _ProfileTile({
    required this.profile,
    required this.isActive,
    required this.onTap,
    required this.onFav,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final sub = profile.subtitle.isNotEmpty
        ? profile.subtitle
        : (profile.serverEndpoint ?? '');
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Material(
        color: theme.colorScheme.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(14),
          side: BorderSide(
            color: isActive
                ? theme.colorScheme.primary
                : theme.colorScheme.outlineVariant,
            width: isActive ? 1.6 : 1.0,
          ),
        ),
        child: InkWell(
          borderRadius: BorderRadius.circular(14),
          onTap: onTap,
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
            child: Row(
              children: [
                Container(
                  width: 32,
                  height: 32,
                  decoration: BoxDecoration(
                    color: theme.colorScheme.primary.withValues(alpha: 0.1),
                    shape: BoxShape.circle,
                  ),
                  alignment: Alignment.center,
                  child: Text(
                    profile.flag.isNotEmpty ? profile.flag : '🌐',
                    style: const TextStyle(fontSize: 18),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        profile.name,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: theme.textTheme.titleSmall?.copyWith(
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      if (sub.isNotEmpty) ...[
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
                    ],
                  ),
                ),
                if (isActive)
                  Padding(
                    padding: const EdgeInsets.only(right: 8),
                    child: Icon(Icons.check_circle_rounded,
                        color: theme.colorScheme.primary, size: 20),
                  ),
                IconButton(
                  visualDensity: VisualDensity.compact,
                  icon: Icon(
                    profile.favorite
                        ? Icons.star_rounded
                        : Icons.star_border_rounded,
                    color: profile.favorite ? Colors.amber : null,
                  ),
                  onPressed: onFav,
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
