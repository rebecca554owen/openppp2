import 'package:flutter/material.dart';
import '../models/config_profile.dart';
import '../models/launch_route_mode.dart';
import '../utils/profile_groups.dart';
import 'app_section_card.dart';

typedef ProfileCallback = void Function(ConfigProfile profile);

/// Grouped profile list used on Home and Profiles pages (iOS layout).
class GroupedProfileList extends StatelessWidget {
  final List<ConfigProfile> profiles;
  final String? activeId;
  final bool shrinkWrap;
  final double? maxHeight;
  final ProfileCallback? onTap;
  final ProfileCallback? onApply;
  final ProfileCallback? onEdit;
  final ProfileCallback? onTogglePin;
  final ProfileCallback? onDelete;

  const GroupedProfileList({
    super.key,
    required this.profiles,
    required this.activeId,
    this.shrinkWrap = false,
    this.maxHeight,
    this.onTap,
    this.onApply,
    this.onEdit,
    this.onTogglePin,
    this.onDelete,
  });

  @override
  Widget build(BuildContext context) {
    final groups = ProfileGroups.fromProfiles(profiles);
    if (groups.isEmpty) {
      return Padding(
        padding: const EdgeInsets.symmetric(vertical: 24),
        child: Center(
          child: Text(
            '暂无配置文件',
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
          ),
        ),
      );
    }

    final list = ListView(
      shrinkWrap: shrinkWrap && maxHeight == null,
      physics: maxHeight != null
          ? const ClampingScrollPhysics()
          : (shrinkWrap ? const NeverScrollableScrollPhysics() : null),
      padding: const EdgeInsets.symmetric(horizontal: 0),
      children: [
        for (var gi = 0; gi < groups.length; gi++) ...[
          AppSectionHeader(groups[gi].title),
          for (var pi = 0; pi < groups[gi].profiles.length; pi++)
            ProfileListTile(
              profile: groups[gi].profiles[pi],
              isActive: groups[gi].profiles[pi].id == activeId,
              position: _tilePosition(pi, groups[gi].profiles.length),
              onTap: onTap,
              onApply: onApply,
              onEdit: onEdit,
              onTogglePin: onTogglePin,
              onDelete: onDelete,
            ),
          if (gi < groups.length - 1) const SizedBox(height: 4),
        ],
      ],
    );

    if (maxHeight != null) {
      return ConstrainedBox(
        constraints: BoxConstraints(maxHeight: maxHeight!),
        child: list,
      );
    }
    return list;
  }

  static ProfileTilePosition _tilePosition(int index, int count) {
    if (count <= 1) return ProfileTilePosition.only;
    if (index == 0) return ProfileTilePosition.first;
    if (index == count - 1) return ProfileTilePosition.last;
    return ProfileTilePosition.middle;
  }
}

enum ProfileTilePosition { first, middle, last, only }

class ProfileListTile extends StatelessWidget {
  final ConfigProfile profile;
  final bool isActive;
  final ProfileTilePosition position;
  final ProfileCallback? onTap;
  final ProfileCallback? onApply;
  final ProfileCallback? onEdit;
  final ProfileCallback? onTogglePin;
  final ProfileCallback? onDelete;

  const ProfileListTile({
    super.key,
    required this.profile,
    required this.isActive,
    this.position = ProfileTilePosition.only,
    this.onTap,
    this.onApply,
    this.onEdit,
    this.onTogglePin,
    this.onDelete,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final sub = profile.subtitle.isNotEmpty
        ? profile.subtitle
        : (profile.serverEndpoint ?? '未配置服务器');

    final radius = _borderRadius();
    return Padding(
      padding: const EdgeInsets.only(bottom: 2),
      child: Material(
        color: theme.colorScheme.surfaceContainerHigh,
        shape: RoundedRectangleBorder(
          borderRadius: radius,
          side: BorderSide(
            color: isActive
                ? theme.colorScheme.primary
                : theme.colorScheme.outlineVariant.withValues(alpha: 0.6),
            width: isActive ? 1.5 : 1,
          ),
        ),
        child: InkWell(
          borderRadius: radius,
          onTap: onTap == null ? null : () => onTap!(profile),
          onLongPress: onEdit == null ? null : () => onEdit!(profile),
          child: Padding(
            padding: const EdgeInsets.fromLTRB(12, 10, 4, 10),
            child: Row(
              children: [
                _FlagAvatar(flag: profile.flag),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Flexible(
                            child: Text(
                              profile.name,
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: theme.textTheme.titleSmall?.copyWith(
                                fontWeight: FontWeight.w700,
                              ),
                            ),
                          ),
                          if (isActive) ...[
                            const SizedBox(width: 6),
                            _ActiveBadge(),
                          ],
                        ],
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
                if (onTogglePin != null)
                  IconButton(
                    visualDensity: VisualDensity.compact,
                    tooltip: profile.favorite ? '取消指定' : '指定',
                    icon: Icon(
                      profile.favorite
                          ? Icons.push_pin_rounded
                          : Icons.push_pin_outlined,
                      size: 20,
                      color: profile.favorite ? Colors.amber.shade700 : null,
                    ),
                    onPressed: () => onTogglePin!(profile),
                  ),
                PopupMenuButton<String>(
                  icon: const Icon(Icons.more_vert_rounded, size: 20),
                  onSelected: (value) {
                    switch (value) {
                      case 'apply':
                        onApply?.call(profile);
                        break;
                      case 'edit':
                        onEdit?.call(profile);
                        break;
                      case 'delete':
                        onDelete?.call(profile);
                        break;
                    }
                  },
                  itemBuilder: (ctx) => [
                    if (!isActive && onApply != null)
                      const PopupMenuItem(
                        value: 'apply',
                        child: ListTile(
                          leading: Icon(Icons.check_circle_outline),
                          title: Text('应用'),
                          contentPadding: EdgeInsets.zero,
                          dense: true,
                        ),
                      ),
                    if (onEdit != null)
                      const PopupMenuItem(
                        value: 'edit',
                        child: ListTile(
                          leading: Icon(Icons.edit_outlined),
                          title: Text('编辑'),
                          contentPadding: EdgeInsets.zero,
                          dense: true,
                        ),
                      ),
                    if (onDelete != null)
                      const PopupMenuItem(
                        value: 'delete',
                        child: ListTile(
                          leading: Icon(Icons.delete_outline),
                          title: Text('删除'),
                          contentPadding: EdgeInsets.zero,
                          dense: true,
                        ),
                      ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  BorderRadius _borderRadius() {
    const r = 14.0;
    switch (position) {
      case ProfileTilePosition.only:
        return BorderRadius.circular(r);
      case ProfileTilePosition.first:
        return const BorderRadius.vertical(top: Radius.circular(r));
      case ProfileTilePosition.middle:
        return BorderRadius.zero;
      case ProfileTilePosition.last:
        return const BorderRadius.vertical(bottom: Radius.circular(r));
    }
  }
}

class _FlagAvatar extends StatelessWidget {
  final String flag;
  const _FlagAvatar({required this.flag});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      width: 36,
      height: 36,
      decoration: BoxDecoration(
        color: theme.colorScheme.primary.withValues(alpha: 0.1),
        shape: BoxShape.circle,
      ),
      alignment: Alignment.center,
      child: Text(
        flag.isNotEmpty ? flag : '🌐',
        style: const TextStyle(fontSize: 20),
      ),
    );
  }
}

class _ActiveBadge extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
      decoration: BoxDecoration(
        color: theme.colorScheme.primary,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Text(
        '使用中',
        style: theme.textTheme.labelSmall?.copyWith(
          color: theme.colorScheme.onPrimary,
          fontWeight: FontWeight.w700,
          letterSpacing: 0.4,
        ),
      ),
    );
  }
}

/// Home status card: connection state, traffic, and quick toggles (iOS layout).
class HomeStatusCard extends StatelessWidget {
  final String statusText;
  final String detailText;
  final bool isConnected;
  final bool isBusy;
  final String buttonLabel;
  final bool buttonEnabled;
  final String uploadText;
  final String downloadText;
  final bool allowLan;
  final bool blockQuic;
  final LaunchRouteMode routeMode;
  final VoidCallback? onConnect;
  final ValueChanged<bool>? onAllowLanChanged;
  final ValueChanged<bool>? onBlockQuicChanged;
  final ValueChanged<LaunchRouteMode>? onRouteModeChanged;

  const HomeStatusCard({
    super.key,
    required this.statusText,
    required this.detailText,
    required this.isConnected,
    required this.isBusy,
    required this.buttonLabel,
    required this.buttonEnabled,
    required this.uploadText,
    required this.downloadText,
    required this.allowLan,
    required this.blockQuic,
    required this.routeMode,
    this.onConnect,
    this.onAllowLanChanged,
    this.onBlockQuicChanged,
    this.onRouteModeChanged,
  });

  Color _accentColor(ThemeData theme) {
    if (isConnected || isBusy) return theme.colorScheme.primary;
    return theme.brightness == Brightness.dark
        ? const Color(0xFF38485C)
        : const Color(0xFF425068);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final accent = _accentColor(theme);

    return Card(
      margin: EdgeInsets.zero,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(18, 18, 18, 16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                _StatusDot(color: accent, pulse: !isConnected && !isBusy),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        statusText,
                        style: theme.textTheme.titleMedium?.copyWith(
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        detailText,
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                          fontFeatures: const [FontFeature.tabularFigures()],
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 8),
                FilledButton(
                  onPressed: buttonEnabled ? onConnect : null,
                  style: FilledButton.styleFrom(
                    backgroundColor: accent,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(
                      horizontal: 18,
                      vertical: 10,
                    ),
                    shape: const StadiumBorder(),
                  ),
                  child: isBusy
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(
                            strokeWidth: 2,
                            color: Colors.white,
                          ),
                        )
                      : Text(buttonLabel),
                ),
              ],
            ),
            const SizedBox(height: 14),
            const Divider(height: 1),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: _SpeedColumn(
                    label: '↑ 上行',
                    value: uploadText,
                    color: const Color(0xFFF59E0B),
                  ),
                ),
                Container(
                  width: 1,
                  height: 42,
                  color: theme.dividerColor.withValues(alpha: 0.55),
                ),
                Expanded(
                  child: _SpeedColumn(
                    label: '↓ 下行',
                    value: downloadText,
                    color: theme.colorScheme.primary,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 14),
            const Divider(height: 1),
            const SizedBox(height: 10),
            Text(
              '快捷开关',
              style: theme.textTheme.labelLarge?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
                fontWeight: FontWeight.w600,
              ),
            ),
            const SizedBox(height: 4),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              value: allowLan,
              title: const Text('局域网代理'),
              subtitle: const Text('HTTP / SOCKS 监听 0.0.0.0'),
              onChanged: onAllowLanChanged,
            ),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              value: blockQuic,
              title: const Text('屏蔽 QUIC'),
              subtitle: const Text('屏蔽 UDP/443 防止 QUIC 绕过'),
              onChanged: onBlockQuicChanged,
            ),
            const SizedBox(height: 4),
            Text('路由模式', style: theme.textTheme.bodyMedium),
            const SizedBox(height: 6),
            SegmentedButton<LaunchRouteMode>(
              showSelectedIcon: false,
              segments: [
                for (final mode in LaunchRouteMode.values)
                  ButtonSegment(value: mode, label: Text(mode.label)),
              ],
              selected: {routeMode},
              onSelectionChanged: (selection) {
                if (selection.isEmpty || onRouteModeChanged == null) return;
                onRouteModeChanged!(selection.first);
              },
            ),
          ],
        ),
      ),
    );
  }
}

class _StatusDot extends StatefulWidget {
  final Color color;
  final bool pulse;

  const _StatusDot({required this.color, required this.pulse});

  @override
  State<_StatusDot> createState() => _StatusDotState();
}

class _StatusDotState extends State<_StatusDot>
    with SingleTickerProviderStateMixin {
  AnimationController? _controller;

  @override
  void initState() {
    super.initState();
    _syncAnimation();
  }

  @override
  void didUpdateWidget(covariant _StatusDot oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.pulse != widget.pulse) _syncAnimation();
  }

  void _syncAnimation() {
    if (widget.pulse) {
      _controller ??= AnimationController(
        vsync: this,
        duration: const Duration(milliseconds: 1600),
      )..repeat(reverse: true);
    } else {
      _controller?.dispose();
      _controller = null;
    }
    if (mounted) setState(() {});
  }

  @override
  void dispose() {
    _controller?.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final opacity = widget.pulse && _controller != null
        ? Tween<double>(begin: 0.38, end: 1).animate(
            CurvedAnimation(parent: _controller!, curve: Curves.easeInOut),
          )
        : const AlwaysStoppedAnimation(1.0);
    return FadeTransition(
      opacity: opacity,
      child: Container(
        width: 12,
        height: 12,
        decoration: BoxDecoration(
          color: widget.color,
          shape: BoxShape.circle,
          boxShadow: [
            BoxShadow(
              color: widget.color.withValues(alpha: 0.42),
              blurRadius: 10,
            ),
          ],
        ),
      ),
    );
  }
}

class _SpeedColumn extends StatelessWidget {
  final String label;
  final String value;
  final Color color;

  const _SpeedColumn({
    required this.label,
    required this.value,
    required this.color,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Column(
      children: [
        Text(
          label,
          style: theme.textTheme.labelMedium?.copyWith(color: color),
        ),
        const SizedBox(height: 4),
        Text(
          value,
          textAlign: TextAlign.center,
          style: theme.textTheme.titleMedium?.copyWith(
            fontWeight: FontWeight.w800,
            fontFeatures: const [FontFeature.tabularFigures()],
          ),
        ),
      ],
    );
  }
}
