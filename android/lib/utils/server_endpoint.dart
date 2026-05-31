import 'dart:io';

class ServerEndpoint {
  final String host;
  final int? port;

  const ServerEndpoint({required this.host, this.port});

  static ServerEndpoint parse(String value) {
    final trimmed = value.trim();
    if (trimmed.isEmpty) return const ServerEndpoint(host: '');

    const scheme = 'ppp://';
    if (trimmed.startsWith(scheme)) {
      final authority = trimmed.substring(scheme.length).split('/').first;
      if (authority.startsWith('[') || ':'.allMatches(authority).length > 1) {
        return _parseAuthority(authority);
      }
    }

    final uri = Uri.tryParse(trimmed);
    if (uri != null && uri.host.isNotEmpty) {
      return ServerEndpoint(host: uri.host, port: uri.hasPort ? uri.port : null);
    }

    if (trimmed.startsWith(scheme)) {
      final authority = trimmed.substring(scheme.length).split('/').first;
      return _parseAuthority(authority);
    }

    return _parseAuthority(trimmed);
  }

  static ServerEndpoint _parseAuthority(String authority) {
    final raw = authority.trim();
    if (raw.isEmpty) return const ServerEndpoint(host: '');

    if (raw.startsWith('[')) {
      final end = raw.indexOf(']');
      if (end > 0) {
        final host = raw.substring(1, end);
        final rest = raw.substring(end + 1);
        final port = rest.startsWith(':') ? int.tryParse(rest.substring(1)) : null;
        return ServerEndpoint(host: host, port: port);
      }
    }

    final colonCount = ':'.allMatches(raw).length;
    if (colonCount > 1) {
      final lastColon = raw.lastIndexOf(':');
      final hostCandidate = raw.substring(0, lastColon);
      final tail = raw.substring(lastColon + 1);
      final port = int.tryParse(tail);
      if (port != null && _isValidIpv6Address(hostCandidate)) {
        return ServerEndpoint(host: hostCandidate, port: port);
      }
      return ServerEndpoint(host: raw);
    }

    final colon = raw.lastIndexOf(':');
    if (colon > 0) {
      final port = int.tryParse(raw.substring(colon + 1));
      if (port != null) {
        return ServerEndpoint(host: raw.substring(0, colon), port: port);
      }
    }
    return ServerEndpoint(host: raw);
  }

  String toPppUrl() {
    final normalizedHost = host.trim();
    final urlHost = _needsIpv6Brackets(normalizedHost)
        ? '[$normalizedHost]'
        : normalizedHost;
    return 'ppp://$urlHost${port != null && port! > 0 ? ':$port' : ''}/';
  }

  static bool _isValidIpv6Address(String value) {
    return InternetAddress.tryParse(value)?.type == InternetAddressType.IPv6;
  }

  static bool _needsIpv6Brackets(String host) =>
      host.contains(':') && !(host.startsWith('[') && host.endsWith(']'));
}
