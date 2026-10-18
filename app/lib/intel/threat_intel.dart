import 'dart:async';
import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;

import '../detection/rule_pack.dart';

enum IntelKind { url, domain, fileHash }

enum IntelStatus { malicious, suspicious, clean, unknown, error }

class IntelVerdict {
  const IntelVerdict({required this.provider, required this.status, this.detail, this.local = false, this.checkedAt});

  final String provider;
  final IntelStatus status;
  final String? detail;

  /// Local detections (rule pack) are shown separately from external reputation.
  final bool local;
  final DateTime? checkedAt;
}

class ProviderHealth {
  DateTime? lastSuccess;
  DateTime? lastFailure;
  String? lastError;
  int consecutiveFailures = 0;

  bool get degraded => consecutiveFailures >= 3;
}

abstract class ThreatIntelProvider {
  String get id;
  String get name;
  bool get isRemote;
  Set<IntelKind> get supports;
  Future<IntelVerdict> lookup(IntelKind kind, String value);
}

/// Offline provider backed by the signed rule pack.
class LocalRulePackProvider implements ThreatIntelProvider {
  LocalRulePackProvider(this.pack);
  final RulePack pack;

  @override
  String get id => 'local';
  @override
  String get name => 'Sentinel rule pack v${pack.version}';
  @override
  bool get isRemote => false;
  @override
  Set<IntelKind> get supports => IntelKind.values.toSet();

  @override
  Future<IntelVerdict> lookup(IntelKind kind, String value) async {
    final hit = switch (kind) {
      IntelKind.fileHash => pack.lookup('file_sha256', value.toLowerCase()),
      IntelKind.domain => pack.lookupDomain(value),
      IntelKind.url => pack.lookupUrl(value) ?? pack.lookupDomain(Uri.tryParse(value)?.host ?? ''),
    };
    return IntelVerdict(
      provider: name,
      local: true,
      status: hit == null ? IntelStatus.unknown : IntelStatus.malicious,
      detail: hit == null ? null : '${hit.family} (${hit.source})',
      checkedAt: DateTime.now(),
    );
  }
}

/// Talks to the optional Sentinel backend, which proxies commercial providers
/// (Google Web Risk, VirusTotal…) so that no API key ever ships in the app.
///
/// Privacy: domains are sent as SHA-256 hashes; full URLs only when the user
/// enabled "detailed URL analysis". Files are never uploaded — only their hash.
class BackendProvider implements ThreatIntelProvider {
  BackendProvider({required this.baseUrl, required this.token, this.sendFullUrls = false, http.Client? client, this.timeout = const Duration(seconds: 8)})
    : _client = client ?? http.Client();

  final Uri baseUrl;
  final String token;
  final bool sendFullUrls;
  final http.Client _client;
  final Duration timeout;

  @override
  String get id => 'backend';
  @override
  String get name => 'Sentinel backend (${baseUrl.host})';
  @override
  bool get isRemote => true;
  @override
  Set<IntelKind> get supports => IntelKind.values.toSet();

  @override
  Future<IntelVerdict> lookup(IntelKind kind, String value) async {
    final body = switch (kind) {
      IntelKind.fileHash => {'type': 'file_sha256', 'value': value.toLowerCase()},
      IntelKind.domain => {'type': 'domain_sha256', 'value': sha256.convert(utf8.encode(value.toLowerCase())).toString()},
      IntelKind.url =>
        sendFullUrls
            ? {'type': 'url', 'value': value}
            : {'type': 'domain_sha256', 'value': sha256.convert(utf8.encode((Uri.tryParse(value)?.host ?? value).toLowerCase())).toString()},
    };
    final res = await _client
        .post(baseUrl.resolve('/v1/reputation'), headers: {'Authorization': 'Bearer $token', 'Content-Type': 'application/json'}, body: jsonEncode(body))
        .timeout(timeout);
    if (res.statusCode == 429) throw IntelRateLimited();
    if (res.statusCode != 200) throw Exception('HTTP ${res.statusCode}');
    final j = jsonDecode(res.body) as Map<String, dynamic>;
    return IntelVerdict(
      provider: '${j['provider'] ?? name}',
      status: IntelStatus.values.firstWhere((s) => s.name == j['verdict'], orElse: () => IntelStatus.unknown),
      detail: j['detail'] as String?,
      checkedAt: DateTime.now(),
    );
  }
}

class IntelRateLimited implements Exception {}

/// Provider-independent façade: caching, timeouts, client-side rate limiting,
/// health tracking and local fallback.
class IntelService {
  IntelService({required this.providers, this.cacheTtl = const Duration(hours: 6), this.maxPerMinute = 20, DateTime Function()? clock})
    : _clock = clock ?? DateTime.now;

  final List<ThreatIntelProvider> providers;
  final Duration cacheTtl;
  final int maxPerMinute;
  final DateTime Function() _clock;
  final Map<String, (DateTime, IntelVerdict)> _cache = {};
  final Map<String, List<DateTime>> _calls = {};
  final Map<String, ProviderHealth> health = {};

  Future<List<IntelVerdict>> lookup(IntelKind kind, String value, {bool allowRemote = false}) async {
    final out = <IntelVerdict>[];
    for (final p in providers) {
      if (!p.supports.contains(kind)) continue;
      if (p.isRemote && !allowRemote) continue;
      final key = '${p.id}|${kind.name}|$value';
      final cached = _cache[key];
      if (cached != null && _clock().difference(cached.$1) < cacheTtl) {
        out.add(cached.$2);
        continue;
      }
      final h = health.putIfAbsent(p.id, ProviderHealth.new);
      if (p.isRemote && !_allow(p.id)) {
        out.add(IntelVerdict(provider: p.name, status: IntelStatus.error, detail: 'rate limited (client)'));
        continue;
      }
      try {
        final v = await p.lookup(kind, value).timeout(const Duration(seconds: 10));
        _cache[key] = (_clock(), v);
        h
          ..lastSuccess = _clock()
          ..consecutiveFailures = 0;
        out.add(v);
      } catch (e) {
        h
          ..lastFailure = _clock()
          ..lastError = e is IntelRateLimited ? 'rate limited (server)' : e.toString().split('\n').first
          ..consecutiveFailures += 1;
        out.add(IntelVerdict(provider: p.name, status: IntelStatus.error, detail: h.lastError));
      }
    }
    return out;
  }

  bool _allow(String id) {
    final now = _clock();
    final list = _calls.putIfAbsent(id, () => [])..removeWhere((t) => now.difference(t) > const Duration(minutes: 1));
    if (list.length >= maxPerMinute) return false;
    list.add(now);
    return true;
  }
}
