import 'package:flutter_test/flutter_test.dart';
import 'package:sentinel_mobile_soc/core/models.dart';
import 'package:sentinel_mobile_soc/detection/rule_pack.dart';
import 'package:sentinel_mobile_soc/engine/scan_engine.dart';
import 'package:sentinel_mobile_soc/engine/scoring.dart';

import 'fixtures.dart';

Finding f(Severity s, Confidence c, Classification k, {FindingCategory cat = FindingCategory.configuration, String id = 'X'}) => Finding(
      ruleId: id,
      ruleVersion: 1,
      platform: DevicePlatform.android,
      title: const LText('t', 't'),
      description: const LText('d', 'd'),
      severity: s,
      confidence: c,
      classification: k,
      category: cat,
      method: const LText('m', 'm'),
      limitations: const LText('l', 'l'),
      component: '$id$s$c$k$cat',
    );

const checked = [CoverageItem('a', LText('a', 'a'), CoverageStatus.checked)];

void main() {
  group('scoring', () {
    test('no findings with coverage = 100 / strong', () {
      final s = SecurityScore.compute([], checked);
      expect(s.score, 100);
      expect(s.posture, Posture.strong);
      expect(s.coverage, 1);
    });

    test('no coverage = unknown posture (never "safe")', () {
      expect(SecurityScore.compute([], []).posture, Posture.unknown);
    });

    test('penalty = weight x confidence x class factor', () {
      final s = SecurityScore.compute([f(Severity.high, Confidence.medium, Classification.exposure)], checked);
      expect(s.score, 100 - (15 * 0.7).round());
      expect(s.posture, Posture.atRisk);
    });

    test('informational and false positives do not reduce the score', () {
      final fp = f(Severity.critical, Confidence.high, Classification.suspicious)..status = RemediationStatus.falsePositive;
      final s = SecurityScore.compute([fp, f(Severity.informational, Confidence.high, Classification.informational)], checked);
      expect(s.score, 100);
    });

    test('confirmed malicious forces critical posture', () {
      final s = SecurityScore.compute([f(Severity.low, Confidence.high, Classification.confirmedMalicious)], checked);
      expect(s.posture, Posture.critical);
    });

    test('per-category cap at 45', () {
      final many = [for (var i = 0; i < 10; i++) f(Severity.critical, Confidence.high, Classification.suspicious, id: 'R$i')];
      expect(SecurityScore.compute(many, checked).score, 55);
    });

    test('coverage excludes not-applicable and counts unavailable', () {
      final s = SecurityScore.compute([], const [
        CoverageItem('a', LText('a', 'a'), CoverageStatus.checked),
        CoverageItem('b', LText('b', 'b'), CoverageStatus.unavailable),
        CoverageItem('c', LText('c', 'c'), CoverageStatus.notApplicable),
      ]);
      expect(s.coverage, 0.5);
    });
  });

  group('scan engine', () {
    test('quick scan skips comprehensive-only rules; comprehensive adds them', () async {
      final engine = ScanEngine();
      final src = FixtureSource(androidSnapshot());
      final quick = await engine.run(source: src, pack: RulePack.empty(), mode: ScanMode.quick);
      final full = await engine.run(source: src, pack: RulePack.empty(), mode: ScanMode.comprehensive);
      final qIds = quick.coverage.map((c) => c.checkId).toSet();
      final fIds = full.coverage.map((c) => c.checkId).toSet();
      expect(qIds.intersection(ScanEngine.comprehensiveOnly), isEmpty);
      expect(fIds, containsAll(['AND-APP-002', 'NET-TLS']));
      expect(full.coverage.firstWhere((c) => c.checkId == 'NET-TLS').status, CoverageStatus.unavailable, reason: 'network checks are opt-in');
    });

    test('collection failure yields an error report, not a clean one', () async {
      final r = await ScanEngine().run(source: FixtureSource(androidSnapshot(), fail: true), pack: RulePack.empty(), mode: ScanMode.quick);
      expect(r.errors, isNotEmpty);
      expect(r.coverage, isEmpty);
      expect(SecurityScore.compute(r.findings, r.coverage).posture, Posture.unknown);
    });

    test('iOS report lists manual checks (installed apps, profiles, call forwarding)', () async {
      final r = await ScanEngine().run(source: FixtureSource(iosSnapshot()), pack: RulePack.empty(), mode: ScanMode.quick);
      final manual = r.coverage.where((c) => c.status == CoverageStatus.unavailable).map((c) => c.checkId);
      expect(manual, containsAll(['IOS-MAN-APPS', 'IOS-MAN-PROFILES', 'MAN-CALLFWD']));
      expect(SecurityScore.compute(r.findings, r.coverage).coverage, lessThan(1));
    });

    test('progress is reported and ends at 100%', () async {
      final seen = <double>[];
      await ScanEngine().run(source: FixtureSource(androidSnapshot()), pack: RulePack.empty(), mode: ScanMode.quick, onProgress: (p) => seen.add(p.fraction));
      expect(seen.first, lessThan(0.5));
      expect(seen.last, 1);
    });

    test('findings are deduplicated by stable id across scans', () async {
      final src = FixtureSource(androidSnapshot(apps: [...benignApps(), stalkerApp()]));
      final a = await ScanEngine().run(source: src, pack: RulePack.empty(), mode: ScanMode.quick);
      final b = await ScanEngine().run(source: src, pack: RulePack.empty(), mode: ScanMode.quick);
      expect(a.findings.map((e) => e.id).toSet(), b.findings.map((e) => e.id).toSet());
      expect(a.findings.map((e) => e.id).toSet().length, a.findings.length);
    });

    test('report JSON round-trip preserves findings and coverage', () async {
      final r = await ScanEngine().run(source: FixtureSource(androidSnapshot(apps: [stalkerApp()])), pack: RulePack.empty(), mode: ScanMode.comprehensive);
      final back = ScanReport.fromJson(r.toJson());
      expect(back.findings.length, r.findings.length);
      expect(back.coverage.length, r.coverage.length);
      expect(back.findings.first.title.fr, r.findings.first.title.fr);
    });
  });
}
