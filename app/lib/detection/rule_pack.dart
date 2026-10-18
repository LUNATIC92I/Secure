import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'yara_lite.dart';

/// Ed25519 public keys allowed to sign rule packs (base64, 32 bytes).
/// Rotate by adding the new key before publishing packs signed with it.
/// The matching private key is never stored in this repository (see tool/README.md).
const trustedRuleSigningKeys = <String>[
  'REPLACED_AT_SIGNING_TIME',
];

class RulePackException implements Exception {
  RulePackException(this.message);
  final String message;
  @override
  String toString() => 'RulePackException: $message';
}

/// Indicator of compromise from a curated, attributed source.
class Indicator {
  Indicator({
    required this.type,
    required this.value,
    required this.family,
    required this.category,
    required this.source,
    this.license,
    this.test = false,
  });

  /// package | cert_sha256 | file_sha256 | domain | url_prefix
  final String type;
  final String value;
  final String family;

  /// malware | stalkerware | phishing | adware | pua | test
  final String category;
  final String source;
  final String? license;

  /// Benign fixture used to exercise the pipeline; flagged in the UI as a test.
  final bool test;

  static const types = {'package', 'cert_sha256', 'file_sha256', 'domain', 'url_prefix'};

  factory Indicator.fromJson(Map<String, dynamic> j) {
    final type = j['type'];
    final value = j['value'];
    if (type is! String || !types.contains(type)) throw RulePackException('bad indicator type: $type');
    if (value is! String || value.isEmpty || value.length > 512) throw RulePackException('bad indicator value');
    if ((type == 'cert_sha256' || type == 'file_sha256') && !RegExp(r'^[0-9a-f]{64}$').hasMatch(value)) {
      throw RulePackException('bad sha256: $value');
    }
    return Indicator(
      type: type,
      value: type == 'domain' || type == 'url_prefix' ? value.toLowerCase() : value,
      family: j['family'] as String? ?? 'unknown',
      category: j['category'] as String? ?? 'malware',
      source: j['source'] as String? ?? 'unknown',
      license: j['license'] as String?,
      test: j['test'] == true,
    );
  }

  Map<String, dynamic> toJson() => {
        'type': type,
        'value': value,
        'family': family,
        'category': category,
        'source': source,
        if (license != null) 'license': license,
        if (test) 'test': true,
      };
}

class RulePack {
  RulePack({
    required this.version,
    required this.issuedAt,
    required this.indicators,
    required this.yaraRules,
    required this.config,
    this.source = 'bundled',
    this.verified = false,
  }) {
    for (final i in indicators) {
      _index.putIfAbsent(i.type, () => {})[i.value] = i;
    }
  }

  final int version;
  final DateTime issuedAt;
  final List<Indicator> indicators;
  final List<YaraRule> yaraRules;
  final Map<String, dynamic> config;
  final String source;
  final bool verified;
  final Map<String, Map<String, Indicator>> _index = {};

  static RulePack empty() =>
      RulePack(version: 0, issuedAt: DateTime.fromMillisecondsSinceEpoch(0), indicators: const [], yaraRules: const [], config: const {});

  Indicator? lookup(String type, String value) => _index[type]?[type == 'domain' ? value.toLowerCase() : value];

  /// Matches a host and every parent domain (sub.evil.example → evil.example).
  Indicator? lookupDomain(String host) {
    final parts = host.toLowerCase().split('.');
    for (var i = 0; i < parts.length - 1; i++) {
      final hit = lookup('domain', parts.sublist(i).join('.'));
      if (hit != null) return hit;
    }
    return null;
  }

  Indicator? lookupUrl(String url) {
    final lower = url.toLowerCase().replaceFirst(RegExp(r'^https?://'), '');
    for (final i in indicators.where((i) => i.type == 'url_prefix')) {
      if (lower.startsWith(i.value)) return i;
    }
    return null;
  }

  int cfgInt(String key, int fallback) => (config[key] as num?)?.toInt() ?? fallback;

  /// Parses and validates a pack. Signature verification is separate so tests can
  /// exercise parsing; production loading always goes through [loadVerified].
  static RulePack parse(String jsonText, {String source = 'bundled', bool verified = false}) {
    final Object? decoded;
    try {
      decoded = jsonDecode(jsonText);
    } on FormatException catch (e) {
      throw RulePackException('invalid JSON: ${e.message}');
    }
    if (decoded is! Map<String, dynamic>) throw RulePackException('root must be an object');
    if (decoded['schema'] != 1) throw RulePackException('unsupported schema ${decoded['schema']}');
    final version = decoded['version'];
    if (version is! int || version < 1) throw RulePackException('bad version');
    final rawIndicators = decoded['indicators'];
    if (rawIndicators is! List || rawIndicators.length > 200000) throw RulePackException('bad indicators');
    final yaraText = decoded['yara'] as String? ?? '';
    final List<YaraRule> yara;
    try {
      yara = YaraLite.parse(yaraText);
    } on FormatException catch (e) {
      throw RulePackException('invalid YARA rules: ${e.message}');
    }
    return RulePack(
      version: version,
      issuedAt: DateTime.tryParse(decoded['issuedAt'] as String? ?? '') ?? DateTime.fromMillisecondsSinceEpoch(0),
      indicators: rawIndicators.map((e) => Indicator.fromJson(Map<String, dynamic>.from(e as Map))).toList(),
      yaraRules: yara,
      config: Map<String, dynamic>.from(decoded['config'] as Map? ?? const {}),
      source: source,
      verified: verified,
    );
  }

  /// Verifies the detached Ed25519 signature against [trustedKeys] before parsing.
  static Future<RulePack> loadVerified(
    Uint8List body,
    String signatureB64, {
    List<String> trustedKeys = trustedRuleSigningKeys,
    String source = 'bundled',
    int? minimumVersion,
  }) async {
    final Uint8List sig;
    try {
      sig = base64Decode(signatureB64.trim());
    } on FormatException {
      throw RulePackException('signature is not base64');
    }
    if (sig.length != 64) throw RulePackException('signature must be 64 bytes');
    final algo = Ed25519();
    var ok = false;
    for (final k in trustedKeys) {
      final Uint8List pub;
      try {
        pub = base64Decode(k);
      } on FormatException {
        continue;
      }
      if (pub.length != 32) continue;
      if (await algo.verify(body, signature: Signature(sig, publicKey: SimplePublicKey(pub, type: KeyPairType.ed25519)))) {
        ok = true;
        break;
      }
    }
    if (!ok) throw RulePackException('signature verification failed');
    final pack = parse(utf8.decode(body), source: source, verified: true);
    if (minimumVersion != null && pack.version < minimumVersion) {
      throw RulePackException('rollback refused: ${pack.version} < $minimumVersion');
    }
    return pack;
  }
}
