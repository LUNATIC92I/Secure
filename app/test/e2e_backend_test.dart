// End-to-end contract test against a running backend. Skipped unless SENTINEL_E2E_URL
// (and SENTINEL_E2E_ADMIN_TOKEN for publishing) are set, e.g.:
//   SENTINEL_E2E_URL=http://127.0.0.1:8000 SENTINEL_E2E_ADMIN_TOKEN=<bootstrap> flutter test test/e2e_backend_test.dart
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sentinel_mobile_soc/intel/threat_intel.dart';
import 'package:sentinel_mobile_soc/services/repository.dart';
import 'package:sentinel_mobile_soc/services/rule_pack_loader.dart';
import 'package:sentinel_mobile_soc/services/secure_store.dart';

void main() {
  final url = Platform.environment['SENTINEL_E2E_URL'];
  final boot = Platform.environment['SENTINEL_E2E_ADMIN_TOKEN'];

  test('register, publish signed pack, app verifies it, reputation lookup', () async {
    final base = Uri.parse(url!);
    Future<String> register([String? bootstrap]) async {
      final r = await http.post(base.resolve('/v1/devices/register'),
          headers: {'Content-Type': 'application/json'}, body: jsonEncode({if (bootstrap != null) 'bootstrap_token': bootstrap}));
      expect(r.statusCode, 201, reason: r.body);
      return (jsonDecode(r.body) as Map)['token'] as String;
    }

    final admin = await register(boot);
    final r = await http.post(base.resolve('/v1/admin/indicators'),
        headers: {'Authorization': 'Bearer $admin', 'Content-Type': 'application/json'},
        body: jsonEncode([
          {'type': 'domain', 'value': 'e2e-phish.example', 'family': 'E2E', 'category': 'phishing', 'source': 'e2e'}
        ]));
    expect(r.statusCode, 201);
    final pub = await http.post(base.resolve('/v1/admin/rules/publish'),
        headers: {'Authorization': 'Bearer $admin', 'Content-Type': 'application/json'}, body: jsonEncode({'yara': '', 'config': {}}));
    expect(pub.statusCode, 201, reason: pub.body);

    final device = await register();
    final dir = await Directory.systemTemp.createTemp('e2e');
    final repo = Repository(SecureStore(keys: MemoryKeyProvider(), directory: dir));
    // Uses the pinned production keys: succeeds only if the backend signs with the matching seed.
    final pack = await RulePackLoader(repo).update(base, device, currentVersion: 0);
    expect(pack.verified, isTrue);
    expect(pack.lookupDomain('login.e2e-phish.example'), isNotNull);

    final provider = BackendProvider(baseUrl: base, token: device);
    final v = await provider.lookup(IntelKind.domain, 'e2e-phish.example');
    expect(v.status, IntelStatus.malicious);
    await dir.delete(recursive: true);
  }, skip: url == null ? 'SENTINEL_E2E_URL not set' : false);
}
