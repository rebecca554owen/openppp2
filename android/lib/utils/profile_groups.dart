import '../models/config_profile.dart';

class ProfileGroup {
  final String title;
  final List<ConfigProfile> profiles;

  const ProfileGroup({required this.title, required this.profiles});

  ProfileGroup copyWithProfiles(List<ConfigProfile> value) =>
      ProfileGroup(title: title, profiles: value);
}

class ProfileGroups {
  ProfileGroups._();

  static List<ProfileGroup> fromProfiles(List<ConfigProfile> profiles) {
    final result = <ProfileGroup>[];
    final pinned = profiles.where((p) => p.favorite).toList();
    if (pinned.isNotEmpty) {
      result.add(ProfileGroup(title: '指定', profiles: pinned));
    }

    for (final profile in profiles.where((p) => !p.favorite)) {
      final title = _groupTitle(profile);
      final index = result.indexWhere((g) => g.title == title);
      if (index >= 0) {
        final group = result[index];
        result[index] = group.copyWithProfiles([...group.profiles, profile]);
      } else {
        result.add(ProfileGroup(title: title, profiles: [profile]));
      }
    }
    return result;
  }

  static String _groupTitle(ConfigProfile profile) {
    final url = profile.subscriptionUrl?.trim() ?? '';
    if (url.isEmpty) return '本地配置';
    final uri = Uri.tryParse(url);
    final host = uri?.host;
    if (host != null && host.isNotEmpty) return '订阅 · $host';
    return '订阅 · $url';
  }
}
