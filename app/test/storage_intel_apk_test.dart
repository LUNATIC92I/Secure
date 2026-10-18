import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:sentinel_mobile_soc/core/models.dart';
import 'package:sentinel_mobile_soc/core/settings.dart';
import 'package:sentinel_mobile_soc/engine/apk_analyzer.dart';
import 'package:sentinel_mobile_soc/intel/threat_intel.dart';
import 'package:sentinel_mobile_soc/services/repository.dart';
import 'package:sentinel_mobile_soc/services/secure_store.dart';

import 'fixtures.dart';

void main() {
  group('encrypted storage', () {
    late Directory dir;
    late SecureStore store;
    setUp(() async {
      dir = await Directory.systemTemp.createTemp('sentinel');
      store = SecureStore(keys: MemoryKeyProvider(), directory: dir);
    });
    tearDown(() async {
      if (await dir.exists()) await dir.delete(recursive: true);
    });

    test('round-trip and ciphertext does not contain plaintext', () async {
      await store.write('doc', {'secret': 'com.system.update.service'});
      expect(await store.read('doc'), {'secret': 'com.system.update.service'});
      final raw = await File('${dir.path}/doc.enc').readAsBytes();
      expect(latin1.decode(raw).contains('com.system.update'), isFalse);
    });

    test('tampered file is treated as absent and reported', () async {
      await store.write('doc', [1, 2, 3]);
      final f = File('${dir.path}/doc.enc');
      final bytes = await f.readAsBytes();
      bytes[bytes.length - 1] ^= 0xff;
      await f.writeAsBytes(bytes);
      String? reported;
      expect(await store.read('doc', onCorrupt: (e) => reported = e), isNull);
      expect(reported, isNotNull);
    });

    test('file renamed to another document fails authentication (AAD)', () async {
      await store.write('a', 1);
      await File('${dir.path}/a.enc').copy('${dir.path}/b.enc');
      expect(await store.read('b'), isNull);
    });

    test('repository retention and settings defaults are privacy-preserving', () async {
      final repo = Repository(store);
      final s = await repo.loadSettings();
      expect(s.cloudIntel, isFalse);
      expect(s.networkChecks, isFalse);
      expect(s.notificationsEnabled, isFalse);
      final old = ScanReport(
          id: 'old', mode: ScanMode.quick, platform: DevicePlatform.android,
          startedAt: DateTime.now().subtract(const Duration(days: 40)), finishedAt: DateTime.now().subtract(const Duration(days: 40)),
          findings: const [], coverage: const []);
      await repo.addReport(old, retentionDays: 90);
      final kept = await repo.addReport(
          ScanReport(id: 'new', mode: ScanMode.quick, platform: DevicePlatform.android, startedAt: DateTime.now(), finishedAt: DateTime.now(), findings: const [], coverage: const []),
          retentionDays: 30);
      expect(kept.map((r) => r.id), ['new']);
      await repo.saveSettings(AppSettings(cloudIntel: true));
      expect((await repo.loadSettings()).cloudIntel, isTrue);
    });

    test('wipe removes everything', () async {
      await store.write('x', 1);
      await store.wipe();
      expect(await store.read('x'), isNull);
    });
  });

  group('threat intelligence', () {
    test('remote providers are skipped without consent (offline mode)', () async {
      var calls = 0;
      final client = MockClient((_) async {
        calls++;
        return http.Response('{}', 200);
      });
      final svc = IntelService(providers: [
        LocalRulePackProvider(await bundledPack()),
        BackendProvider(baseUrl: Uri.parse('https://intel.example'), token: 't', client: client),
      ]);
      final v = await svc.lookup(IntelKind.fileHash, '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f');
      expect(calls, 0);
      expect(v.single.local, isTrue);
      expect(v.single.status, IntelStatus.malicious);
    });

    test('domains are hashed by default; results cached; errors tracked', () async {
      final bodies = <Map<String, dynamic>>[];
      var fail = false;
      final client = MockClient((req) async {
        if (fail) return http.Response('boom', 500);
        bodies.add(jsonDecode(req.body) as Map<String, dynamic>);
        expect(req.headers['Authorization'], 'Bearer t');
        return http.Response(jsonEncode({'verdict': 'clean', 'provider': 'mock'}), 200);
      });
      final svc = IntelService(providers: [BackendProvider(baseUrl: Uri.parse('https://intel.example'), token: 't', client: client)]);
      final v = await svc.lookup(IntelKind.url, 'https://secret-token.example.com/reset?t=abc', allowRemote: true);
      expect(v.single.status, IntelStatus.clean);
      expect(bodies.single['type'], 'domain_sha256');
      expect(bodies.single['value'], isNot(contains('secret-token')));
      await svc.lookup(IntelKind.url, 'https://secret-token.example.com/reset?t=abc', allowRemote: true);
      expect(bodies, hasLength(1), reason: 'cached');
      fail = true;
      for (var i = 0; i < 3; i++) {
        await svc.lookup(IntelKind.domain, 'd$i.example', allowRemote: true);
      }
      expect(svc.health['backend']!.degraded, isTrue);
    });

    test('client-side rate limiting', () async {
      final client = MockClient((_) async => http.Response(jsonEncode({'verdict': 'unknown'}), 200));
      final svc = IntelService(providers: [BackendProvider(baseUrl: Uri.parse('https://i.example'), token: 't', client: client)], maxPerMinute: 2);
      final results = [for (var i = 0; i < 3; i++) (await svc.lookup(IntelKind.domain, 'x$i.example', allowRemote: true)).single];
      expect(results.last.status, IntelStatus.error);
      expect(results.last.detail, contains('rate limited'));
    });
  });

  group('APK analysis (pure part)', () {
    test('EICAR hash is confirmed; capabilities and YARA are heuristic', () async {
      final pack = await bundledPack();
      final r = ApkAnalyzer(pack).build(
        fileName: 'sample.apk',
        now: DateTime(2026),
        native: {
          'parsed': true,
          'sha256': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
          'package': 'io.sentinel.testfixture.trojan',
          'requestedPermissions': ['${p}RECORD_AUDIO', '${p}READ_SMS', '${p}READ_CALL_LOG', '${p}ACCESS_BACKGROUND_LOCATION', '${p}SEND_SMS', '${p}RECEIVE_SMS'],
          'boundServicePermissions': ['${p}BIND_ACCESSIBILITY_SERVICE'],
          'signingSha256': ['d' * 64],
          'targetSdk': 22,
          'debuggable': true,
          'sizeBytes': 1000,
        },
        scan: {
          'entries': 5,
          'dexCount': 1,
          'nativeAbis': [],
          'embeddedPayloads': ['assets/payload.dex'],
          'yara': [
            {'rule': 'Dynamic_Code_Loading', 'entry': 'classes.dex', 'strings': [r'$a', r'$c'], 'meta': {'severity': 'low'}}
          ],
        },
      );
      Finding byRule(String id) => r.findings.firstWhere((f) => f.ruleId == id);
      expect(byRule('APK-IOC-FILE').classification, Classification.confirmedMalicious);
      expect(byRule('APK-IOC-PACKAGE').classification, Classification.suspicious);
      expect(byRule('APK-CAP-001').classification, Classification.suspicious);
      expect(byRule('APK-CAP-001').confidence, Confidence.low);
      expect(byRule('APK-YARA-Dynamic_Code_Loading').classification, Classification.suspicious);
      expect(r.findings.map((f) => f.ruleId), containsAll(['APK-CAP-002', 'APK-CFG-001', 'APK-CFG-002', 'APK-STR-001']));
      expect(r.findings.first.severity, Severity.critical, reason: 'sorted by severity');
    });

    test('benign APK metadata yields no findings', () async {
      final r = ApkAnalyzer(await bundledPack()).build(
        fileName: 'ok.apk',
        now: DateTime(2026),
        native: {'parsed': true, 'sha256': 'e' * 64, 'package': 'com.example.ok', 'requestedPermissions': ['${p}INTERNET'], 'signingSha256': ['f' * 64], 'targetSdk': 35},
        scan: {'yara': [], 'embeddedPayloads': []},
      );
      expect(r.findings, isEmpty);
    });
  });
}
