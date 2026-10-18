import 'package:flutter_test/flutter_test.dart';
import 'package:sentinel_mobile_soc/core/models.dart';
import 'package:sentinel_mobile_soc/detection/android_rules.dart';
import 'package:sentinel_mobile_soc/detection/common_rules.dart';
import 'package:sentinel_mobile_soc/detection/rule.dart';
import 'package:sentinel_mobile_soc/detection/rule_pack.dart';

import 'fixtures.dart';

List<Finding> runAll(RuleContext ctx) => [
      for (final r in [...androidRules, ...commonRules].where((r) => r.platforms.contains(ctx.platform) && r.available(ctx))) ...r.evaluate(ctx),
    ];

void main() {
  final now = DateTime(2026, 10, 18);
  final empty = RulePack.empty();

  group('benign device (false-positive guard)', () {
    test('ordinary phone produces no medium+ findings', () {
      final f = runAll(RuleContext(snapshot: androidSnapshot(), pack: empty, now: now));
      final notable = f.where((x) => x.severity.index >= Severity.medium.index).toList();
      expect(notable, isEmpty, reason: notable.map((e) => e.ruleId).join(','));
    });

    test('messaging app with mic+SMS+contacts is not flagged as stalkerware', () {
      final f = const StalkerwareCorrelationRule().evaluate(RuleContext(snapshot: androidSnapshot(), pack: empty, now: now));
      expect(f, isEmpty);
    });

    test('common sensitive permission alone is never "confirmed malicious"', () {
      final f = runAll(RuleContext(snapshot: androidSnapshot(), pack: empty, now: now));
      expect(f.where((x) => x.classification == Classification.confirmedMalicious), isEmpty);
    });
  });

  group('stalkerware scenario', () {
    final snap = androidSnapshot(
      device: cleanAndroidDevice()
        ..['accessibilityServices'] = [
          {'id': 'com.system.update.service/.A', 'package': 'com.system.update.service', 'isSystem': false, 'canRetrieveWindowContent': true}
        ]
        ..['deviceAdmins'] = [
          {'package': 'com.system.update.service', 'component': 'com.system.update.service/.Admin', 'isDeviceOwner': false, 'isProfileOwner': false}
        ]
        ..['notificationListeners'] = ['com.system.update.service/.N'],
      apps: [...benignApps(), stalkerApp()],
    );

    test('correlation rule flags hidden side-loaded app as suspicious, high severity', () {
      final f = const StalkerwareCorrelationRule().evaluate(RuleContext(snapshot: snap, pack: empty, now: now)).toList();
      expect(f, hasLength(1));
      expect(f.single.component, 'com.system.update.service');
      expect(f.single.classification, Classification.suspicious);
      expect(f.single.severity, Severity.high);
      expect(f.single.confidence, Confidence.medium);
      expect(int.parse(f.single.evidence['score']!), greaterThanOrEqualTo(9));
    });

    test('accessibility, admin and notification rules each elevate side-loaded app', () {
      final ctx = RuleContext(snapshot: snap, pack: empty, now: now);
      for (final r in [const AccessibilityRule(), const DeviceAdminRule(), const NotificationListenerRule()]) {
        final f = r.evaluate(ctx).single;
        expect(f.classification, Classification.suspicious, reason: r.id);
        expect(f.remediation, isNotEmpty);
      }
    });

    test('remediation never acts silently: uninstall is an explicit step', () {
      final f = const StalkerwareCorrelationRule().evaluate(RuleContext(snapshot: snap, pack: empty, now: now)).single;
      expect(f.remediation.where((s) => s.action == 'uninstall').single.package, 'com.system.update.service');
    });
  });

  group('indicator matching', () {
    test('package-name match is suspicious, cert match is confirmed', () {
      final pack = packWith([
        {'type': 'package', 'value': 'com.example.notes', 'family': 'X', 'category': 'stalkerware', 'source': 'test'},
        {'type': 'cert_sha256', 'value': 'b' * 64, 'family': 'Y', 'category': 'malware', 'source': 'test'},
      ]);
      final snap = androidSnapshot(apps: [...benignApps(), app('com.other', certs: ['b' * 64])]);
      final f = const IndicatorMatchRule().evaluate(RuleContext(snapshot: snap, pack: pack, now: now)).toList();
      final byPkg = {for (final x in f) x.component: x};
      expect(byPkg['com.example.notes']!.classification, Classification.suspicious);
      expect(byPkg['com.other']!.classification, Classification.confirmedMalicious);
      expect(byPkg['com.other']!.confidence, Confidence.high);
    });
  });

  group('configuration & integrity', () {
    test('no lock screen, ADB, old patch, root and unlocked bootloader are reported', () {
      final d = cleanAndroidDevice(patch: '2025-01-01')
        ..['deviceSecure'] = false
        ..['adbEnabled'] = true
        ..['root'] = {'suPaths': ['/system/xbin/su'], 'rootManagers': ['com.topjohnwu.magisk'], 'testKeys': false}
        ..['bootProps'] = {'ro.boot.verifiedbootstate': 'orange', 'ro.boot.flash.locked': '0'};
      final ids = runAll(RuleContext(snapshot: androidSnapshot(device: d), pack: empty, now: now)).map((f) => f.ruleId).toSet();
      expect(ids, containsAll(['AND-CFG-001', 'AND-CFG-003', 'AND-CFG-005', 'AND-INT-001', 'AND-INT-002']));
    });

    test('root is exposure, never confirmed malicious', () {
      final d = cleanAndroidDevice()..['root'] = {'suPaths': ['/sbin/su'], 'rootManagers': [], 'testKeys': true};
      final f = const RootRule().evaluate(RuleContext(snapshot: androidSnapshot(device: d), pack: empty, now: now)).single;
      expect(f.classification, Classification.exposure);
    });

    test('patch thresholds come from the rule pack', () {
      final d = cleanAndroidDevice(patch: '2026-06-01');
      final strict = packWith([], config: {'androidPatchWarnDays': 30});
      expect(const PatchLevelRule().evaluate(RuleContext(snapshot: androidSnapshot(device: d), pack: strict, now: now)), hasLength(1));
      expect(const PatchLevelRule().evaluate(RuleContext(snapshot: androidSnapshot(device: d), pack: empty, now: now)), hasLength(1));
      final lax = packWith([], config: {'androidPatchWarnDays': 400});
      expect(const PatchLevelRule().evaluate(RuleContext(snapshot: androidSnapshot(device: d), pack: lax, now: now)), isEmpty);
    });

    test('user CA, proxy and open Wi-Fi', () {
      final d = cleanAndroidDevice()
        ..['userCaCertificates'] = [
          {'subject': 'CN=Corp Proxy CA', 'issuer': 'CN=Corp Proxy CA', 'sha256': 'c' * 64}
        ];
      final s = androidSnapshot(device: d, network: wifiNetwork(security: 'open', proxy: {'host': '10.0.0.1', 'port': 8080}));
      final ids = runAll(RuleContext(snapshot: s, pack: empty, now: now)).map((f) => f.ruleId).toSet();
      expect(ids, containsAll(['AND-NET-001', 'NET-001', 'NET-003']));
    });

    test('unavailable probe makes the rule unavailable instead of passing', () {
      final d = cleanAndroidDevice()..['notificationListeners'] = null;
      expect(const NotificationListenerRule().available(RuleContext(snapshot: androidSnapshot(device: d), pack: empty, now: now)), isFalse);
    });
  });

  group('iOS', () {
    test('passcode missing and jailbreak indicators', () {
      final s = iosSnapshot(passcode: false, jailbreak: {'paths': ['/Applications/Cydia.app'], 'schemes': [], 'dylibs': ['/usr/lib/TweakInject.dylib'], 'sandboxWritable': false});
      final f = runAll(RuleContext(snapshot: s, pack: empty, now: now));
      expect(f.map((e) => e.ruleId), containsAll(['IOS-CFG-001', 'IOS-INT-001']));
      expect(f.firstWhere((e) => e.ruleId == 'IOS-INT-001').confidence, Confidence.medium);
    });

    test('Android-only rules never run on iOS', () {
      final f = runAll(RuleContext(snapshot: iosSnapshot(), pack: empty, now: now));
      expect(f.where((e) => e.ruleId.startsWith('AND-')), isEmpty);
    });

    test('outdated iOS is flagged from rule-pack config', () {
      final pack = packWith([], config: {'iosLatestMajor': 26});
      expect(const IosVersionRule().evaluate(RuleContext(snapshot: iosSnapshot(version: '17.5'), pack: pack, now: now)), hasLength(1));
      expect(const IosVersionRule().evaluate(RuleContext(snapshot: iosSnapshot(version: '25.1'), pack: pack, now: now)), isEmpty);
    });
  });

  test('every rule documents id, version, confidence model and false positives', () {
    final ids = <String>{};
    for (final r in [...androidRules, ...commonRules]) {
      expect(ids.add(r.id), isTrue, reason: 'duplicate ${r.id}');
      expect(r.version, greaterThan(0));
      expect(r.confidenceModel.en, isNotEmpty);
      expect(r.knownFalsePositives.fr, isNotEmpty);
      expect(r.name.fr, isNotEmpty);
    }
  });
}
