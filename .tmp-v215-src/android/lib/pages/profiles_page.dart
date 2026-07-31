import 'package:flutter/material.dart';
import '../models/config_profile.dart';
import '../services/profile_store.dart';
import '../services/subscription_service.dart';
import '../widgets/profile_ui.dart';
import 'profile_edit_page.dart';

class ProfilesPage extends StatefulWidget {
  const ProfilesPage({super.key});

  @override
  State<ProfilesPage> createState() => _ProfilesPageState();
}

class _ProfilesPageState extends State<ProfilesPage> {
  final _store = ProfileStore();
  List<ConfigProfile> _profiles = const [];
  String? _activeId;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
    _store.changes.listen((_) {
      if (mounted) _load();
    });
  }

  Future<void> _load() async {
    final list = await _store.getProfiles();
    final active = await _store.getActive();
    if (!mounted) return;
    setState(() {
      _profiles = list;
      _activeId = active?.id;
      _loading = false;
    });
  }

  Future<void> _add() async {
    final ok = await Navigator.of(context).push<bool>(
      MaterialPageRoute(builder: (_) => const ProfileEditPage()),
    );
    if (ok == true) await _load();
  }

  Future<String?> _askSubscriptionUrl() async {
    final controller = TextEditingController();
    try {
      return await showDialog<String>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('导入远程订阅'),
          content: TextField(
            controller: controller,
            keyboardType: TextInputType.url,
            autofocus: true,
            decoration: const InputDecoration(
              labelText: '订阅 URL',
              hintText: 'https://example.com/openppp2.json',
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(),
              child: const Text('取消'),
            ),
            FilledButton(
              onPressed: () => Navigator.of(ctx).pop(controller.text.trim()),
              child: const Text('导入'),
            ),
          ],
        ),
      );
    } finally {
      controller.dispose();
    }
  }

  Future<void> _importSubscription() async {
    final url = await _askSubscriptionUrl();
    if (url == null || url.isEmpty) return;

    var progressShown = false;
    if (mounted) {
      progressShown = true;
      showDialog<void>(
        context: context,
        barrierDismissible: false,
        builder: (_) => const Center(child: CircularProgressIndicator()),
      );
    }

    try {
      final subscription = await SubscriptionService().fetch(url);
      final count = await _store.upsertSubscription(
        url: url,
        subscription: subscription,
      );
      if (!mounted) return;
      if (progressShown) Navigator.of(context, rootNavigator: true).pop();
      await _load();
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('已导入/更新 $count 个节点')),
      );
    } catch (e) {
      if (!mounted) return;
      if (progressShown) Navigator.of(context, rootNavigator: true).pop();
      await showDialog<void>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('订阅导入失败'),
          content: SelectableText(e.toString()),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(),
              child: const Text('关闭'),
            ),
          ],
        ),
      );
    }
  }

  Future<void> _edit(ConfigProfile p) async {
    final ok = await Navigator.of(context).push<bool>(
      MaterialPageRoute(builder: (_) => ProfileEditPage(profile: p)),
    );
    if (ok == true) await _load();
  }

  Future<void> _delete(ConfigProfile p) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('删除配置'),
        content: Text('确定要删除「${p.name}」吗？'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('取消'),
          ),
          FilledButton.tonal(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('删除'),
          ),
        ],
      ),
    );
    if (ok == true) {
      await _store.remove(p.id);
      await _load();
    }
  }

  Future<void> _setActive(ConfigProfile p) async {
    await _store.setActive(p.id);
    await _load();
  }

  Future<void> _togglePin(ConfigProfile p) async {
    await _store.toggleFavorite(p.id);
    await _load();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('配置文件'),
        centerTitle: true,
        actions: [
          PopupMenuButton<String>(
            icon: const Icon(Icons.more_horiz_rounded),
            onSelected: (value) {
              switch (value) {
                case 'subscription':
                  _importSubscription();
                  break;
                case 'add':
                  _add();
                  break;
              }
            },
            itemBuilder: (_) => const [
              PopupMenuItem(
                value: 'subscription',
                child: ListTile(
                  leading: Icon(Icons.cloud_download_outlined),
                  title: Text('导入远程订阅'),
                  contentPadding: EdgeInsets.zero,
                  dense: true,
                ),
              ),
              PopupMenuItem(
                value: 'add',
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
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : Padding(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 80),
              child: GroupedProfileList(
                profiles: _profiles,
                activeId: _activeId,
                onTap: _edit,
                onApply: _setActive,
                onEdit: _edit,
                onTogglePin: _togglePin,
                onDelete: _delete,
              ),
            ),
      floatingActionButton: FloatingActionButton(
        onPressed: _add,
        tooltip: '新增配置',
        child: const Icon(Icons.add_rounded),
      ),
    );
  }
}
