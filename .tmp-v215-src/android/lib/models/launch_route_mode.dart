/// Routing preset aligned with the iOS LaunchRouteMode.
enum LaunchRouteMode {
  geo,
  global,
  basic;

  String get label {
    switch (this) {
      case LaunchRouteMode.geo:
        return 'GEO 分流';
      case LaunchRouteMode.global:
        return '全局模式';
      case LaunchRouteMode.basic:
        return '基础规则';
    }
  }

  static LaunchRouteMode fromOptions(Map<String, dynamic> options) {
    final explicit = options['routeMode']?.toString();
    if (explicit != null) {
      for (final mode in LaunchRouteMode.values) {
        if (mode.name == explicit) return mode;
      }
    }
    final geo = options['geoRules'];
    final geoEnabled = geo is Map && geo['enabled'] == true;
    if (geoEnabled) return LaunchRouteMode.geo;
    final bypass = (options['bypassIpList'] ?? '').toString().trim();
    if (bypass.isEmpty) return LaunchRouteMode.global;
    return LaunchRouteMode.basic;
  }

  static Map<String, dynamic> applyTo(
    Map<String, dynamic> options,
    LaunchRouteMode mode,
  ) {
    final out = Map<String, dynamic>.from(options);
    out['routeMode'] = mode.name;
    final geo = out['geoRules'] is Map
        ? Map<String, dynamic>.from(out['geoRules'] as Map)
        : <String, dynamic>{};
    switch (mode) {
      case LaunchRouteMode.geo:
        geo['enabled'] = true;
        break;
      case LaunchRouteMode.global:
        geo['enabled'] = false;
        out['bypassIpList'] = '';
        break;
      case LaunchRouteMode.basic:
        geo['enabled'] = false;
        if ((out['bypassIpList'] ?? '').toString().trim().isEmpty) {
          out['bypassIpList'] =
              '10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16\n169.254.0.0/16\n100.64.0.0/10';
        }
        break;
    }
    out['geoRules'] = geo;
    return out;
  }
}
