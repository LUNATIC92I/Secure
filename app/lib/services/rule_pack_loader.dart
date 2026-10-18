import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;

import '../detection/rule_pack.dart';
import 'repository.dart';

/// Loads the newest valid rule pack: a downloaded update if its signature verifies
/// and it is not older than the bundled one, else the bundled pack.
class RulePackLoader {
  RulePackLoader(this.repo, {AssetBundle? bundle}) : _bundle = bundle ?? rootBundle;

  final Repository repo;
  final AssetBundle _bundle;
  String? lastError;

  Future<RulePack> load({int minimumVersion = 0}) async {
    final body = await _bundle.loadString('assets/rules/rulepack.json');
    final sig = await _bundle.loadString('assets/rules/rulepack.json.sig');
    RulePack bundled;
    try {
      bundled = await RulePack.loadVerified(Uint8List.fromList(utf8.encode(body)), sig, source: 'bundled');
    } on RulePackException catch (e) {
      // Never run unverified content: fall back to an empty pack and report it.
      lastError = 'Bundled rule pack rejected: ${e.message}';
      bundled = RulePack.empty();
    }
    final stored = await repo.loadRulePack();
    if (stored == null) return bundled;
    try {
      final updated = await RulePack.loadVerified(Uint8List.fromList(utf8.encode(stored.$1)), stored.$2, source: 'update', minimumVersion: minimumVersion);
      return updated.version >= bundled.version ? updated : bundled;
    } on RulePackException catch (e) {
      lastError = 'Stored update rejected: ${e.message}';
      return bundled;
    }
  }

  /// Downloads `/v1/rules/latest` from the configured backend and validates it
  /// before persisting. Returns the new pack or throws.
  Future<RulePack> update(Uri backend, String token, {required int currentVersion}) async {
    final res = await http.get(backend.resolve('/v1/rules/latest'), headers: {'Authorization': 'Bearer $token'}).timeout(const Duration(seconds: 15));
    if (res.statusCode != 200) throw RulePackException('HTTP ${res.statusCode}');
    final j = jsonDecode(res.body) as Map<String, dynamic>;
    final body = j['body'] as String? ?? '';
    final sig = j['signature'] as String? ?? '';
    final pack = await RulePack.loadVerified(Uint8List.fromList(utf8.encode(body)), sig, source: 'update', minimumVersion: currentVersion);
    await repo.saveRulePack(body, sig);
    return pack;
  }
}
