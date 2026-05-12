import 'dart:convert';

/// One JSON snapshot kept in profile history (most recent first).
class ConfigSnapshot {
  final int timestampMs;
  final String json;
  const ConfigSnapshot({required this.timestampMs, required this.json});

  Map<String, dynamic> toMap() => {'ts': timestampMs, 'json': json};

  factory ConfigSnapshot.fromMap(Map<String, dynamic> m) => ConfigSnapshot(
        timestampMs: (m['ts'] is int) ? m['ts'] as int : 0,
        json: (m['json'] ?? '').toString(),
      );
}

/// A single OpenPPP2 client config profile (one "Location").
class ConfigProfile {
  final String id;
  String name;
  String subtitle;
  String flag;
  String json;
  bool favorite;

  /// Per-profile VPN launch options (TUN / DNS / Geo bypass / etc).
  /// When empty, the global `ProfileStore.defaultOptions` is used.
  /// Schema matches `ProfileStore.defaultOptions` keys.
  Map<String, dynamic> options;

  /// Most-recent-first list of previous JSON values, capped at [historyLimit].
  List<ConfigSnapshot> history;

  static const int historyLimit = 8;

  ConfigProfile({
    required this.id,
    required this.name,
    this.subtitle = '',
    this.flag = '',
    required this.json,
    this.favorite = false,
    Map<String, dynamic>? options,
    List<ConfigSnapshot>? history,
  })  : options = options ?? <String, dynamic>{},
        history = history ?? <ConfigSnapshot>[];

  Map<String, dynamic> toMap() => {
        'id': id,
        'name': name,
        'subtitle': subtitle,
        'flag': flag,
        'json': json,
        'favorite': favorite,
        'options': options,
        'history': history.map((h) => h.toMap()).toList(),
      };

  factory ConfigProfile.fromMap(Map<String, dynamic> m) {
    final rawHistory = m['history'];
    final history = <ConfigSnapshot>[];
    if (rawHistory is List) {
      for (final item in rawHistory) {
        if (item is Map) {
          history.add(ConfigSnapshot.fromMap(Map<String, dynamic>.from(item)));
        }
      }
    }
    final rawOptions = m['options'];
    final options = (rawOptions is Map)
        ? Map<String, dynamic>.from(rawOptions)
        : <String, dynamic>{};
    return ConfigProfile(
      id: (m['id'] ?? '').toString(),
      name: (m['name'] ?? '').toString(),
      subtitle: (m['subtitle'] ?? '').toString(),
      flag: (m['flag'] ?? '').toString(),
      json: (m['json'] ?? '').toString(),
      favorite: m['favorite'] == true,
      options: options,
      history: history,
    );
  }

  /// Try to derive `host:port` from the JSON `client.server` URL.
  String? get serverEndpoint {
    try {
      final decoded = jsonDecode(json);
      if (decoded is Map) {
        final client = decoded['client'];
        if (client is Map) {
          final s = client['server']?.toString();
          if (s == null || s.isEmpty) return null;
          final uri = Uri.tryParse(s);
          if (uri != null && uri.host.isNotEmpty) {
            final port = uri.hasPort ? ':${uri.port}' : '';
            return '${uri.host}$port';
          }
        }
      }
    } catch (_) {}
    return null;
  }

  ConfigProfile copyWith({
    String? name,
    String? subtitle,
    String? flag,
    String? json,
    bool? favorite,
    Map<String, dynamic>? options,
    List<ConfigSnapshot>? history,
  }) =>
      ConfigProfile(
        id: id,
        name: name ?? this.name,
        subtitle: subtitle ?? this.subtitle,
        flag: flag ?? this.flag,
        json: json ?? this.json,
        favorite: favorite ?? this.favorite,
        options: options ?? this.options,
        history: history ?? this.history,
      );
}
