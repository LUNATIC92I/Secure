import 'dart:async';
import 'dart:math';

import '../core/models.dart';
import '../core/snapshot.dart';
import '../detection/android_rules.dart';
import '../detection/common_rules.dart';
import '../detection/rule.dart';
import '../detection/rule_pack.dart';
import 'network_probe.dart';

/// Source of raw device observations; the production implementation talks to the
/// native plugin, tests inject fixtures.
abstract class SnapshotSource {
  Future<DeviceSnapshot> collect({required bool includeApps});
}

class ScanProgress {
  const ScanProgress(this.fraction, this.stage);
  final double fraction;
  final LText stage;
}

class ScanEngine {
  ScanEngine({List<DetectionRule>? rules, this.networkProbe}) : rules = rules ?? [...androidRules, ...commonRules];

  final List<DetectionRule> rules;
  final NetworkProbe? networkProbe;

  /// Rules skipped by quick scans because they enumerate every app individually and
  /// rarely change the posture on their own.
  static const comprehensiveOnly = {'AND-APP-002', 'AND-APP-003', 'AND-APP-004', 'AND-LOC-001', 'NET-005'};

  Future<ScanReport> run({
    required SnapshotSource source,
    required RulePack pack,
    required ScanMode mode,
    bool background = false,
    bool networkChecksEnabled = false,
    void Function(ScanProgress)? onProgress,
    DateTime Function() clock = DateTime.now,
  }) async {
    final started = clock();
    final errors = <String>[];
    onProgress?.call(const ScanProgress(0.05, LText('Collecting device posture', 'Collecte de l’état de l’appareil')));
    final DeviceSnapshot snap;
    try {
      snap = await source.collect(includeApps: true);
    } catch (e) {
      return ScanReport(
        id: _id(started),
        mode: mode,
        platform: DevicePlatform.unknown,
        startedAt: started,
        finishedAt: clock(),
        findings: const [],
        coverage: const [],
        errors: ['collection failed: $e'],
        rulePackVersion: pack.version,
        background: background,
      );
    }
    onProgress?.call(const ScanProgress(0.45, LText('Evaluating detection rules', 'Évaluation des règles de détection')));

    final ctx = RuleContext(snapshot: snap, pack: pack, now: started);
    final findings = <String, Finding>{};
    final coverage = <CoverageItem>[];
    final applicable = rules.where((r) => r.platforms.contains(snap.platform)).toList();
    for (var i = 0; i < applicable.length; i++) {
      final rule = applicable[i];
      if (mode == ScanMode.quick && comprehensiveOnly.contains(rule.id)) continue;
      if (!rule.available(ctx)) {
        coverage.add(
          CoverageItem(
            rule.id,
            rule.coverageLabel,
            CoverageStatus.unavailable,
            note: const LText('Not exposed by the OS on this device', 'Non exposé par l’OS sur cet appareil'),
          ),
        );
        continue;
      }
      try {
        for (final f in rule.evaluate(ctx)) {
          findings[f.id] = f;
        }
        coverage.add(CoverageItem(rule.id, rule.coverageLabel, CoverageStatus.checked));
      } catch (e) {
        errors.add('${rule.id}: $e');
        coverage.add(CoverageItem(rule.id, rule.coverageLabel, CoverageStatus.error));
      }
      onProgress?.call(
        ScanProgress(0.45 + 0.35 * (i + 1) / applicable.length, const LText('Evaluating detection rules', 'Évaluation des règles de détection')),
      );
    }

    if (mode != ScanMode.quick) {
      onProgress?.call(const ScanProgress(0.85, LText('Checking network integrity', 'Vérification de l’intégrité réseau')));
      if (networkChecksEnabled && networkProbe != null && snap.network['connected'] == true) {
        try {
          final res = await networkProbe!.run(snap.platform, started);
          for (final f in res.findings) {
            findings[f.id] = f;
          }
          coverage.add(
            CoverageItem(
              'NET-TLS',
              const LText('TLS certificate validation', 'Validation des certificats TLS'),
              res.completed ? CoverageStatus.checked : CoverageStatus.error,
            ),
          );
        } catch (e) {
          errors.add('network probe: $e');
          coverage.add(const CoverageItem('NET-TLS', LText('TLS certificate validation', 'Validation des certificats TLS'), CoverageStatus.error));
        }
      } else {
        coverage.add(
          CoverageItem(
            'NET-TLS',
            const LText('TLS certificate validation', 'Validation des certificats TLS'),
            CoverageStatus.unavailable,
            note: networkChecksEnabled
                ? const LText('Offline', 'Hors ligne')
                : const LText('Disabled in Privacy settings (contacts public hosts)', 'Désactivé dans Confidentialité (contacte des hôtes publics)'),
          ),
        );
      }
    }

    coverage.addAll(manualChecks(snap));
    if (snap.platform == DevicePlatform.android && snap.appInventoryLimited) {
      errors.add('Package visibility appears limited; app inventory may be incomplete.');
    }
    onProgress?.call(const ScanProgress(1, LText('Done', 'Terminé')));
    return ScanReport(
      id: _id(started),
      mode: mode,
      platform: snap.platform,
      startedAt: started,
      finishedAt: clock(),
      findings: findings.values.toList()..sort((a, b) => b.severity.index.compareTo(a.severity.index)),
      coverage: coverage,
      errors: errors,
      rulePackVersion: pack.version,
      appsAnalyzed: snap.apps.length,
      background: background,
    );
  }

  /// Surfaces that no standard app can inspect: listed so the user knows to verify them.
  static List<CoverageItem> manualChecks(DeviceSnapshot snap) {
    if (snap.platform == DevicePlatform.ios) {
      return const [
        CoverageItem(
          'IOS-MAN-APPS',
          LText('Installed apps', 'Apps installées'),
          CoverageStatus.unavailable,
          note: LText(
            'iOS does not let apps list other apps. Review Settings → Privacy & Security and App Privacy Report.',
            'iOS ne permet pas de lister les autres apps. Vérifiez Réglages → Confidentialité et sécurité et le Rapport de confidentialité.',
          ),
        ),
        CoverageItem(
          'IOS-MAN-PROFILES',
          LText('Configuration profiles / MDM', 'Profils de configuration / MDM'),
          CoverageStatus.unavailable,
          note: LText(
            'Check Settings → General → VPN & Device Management for profiles you do not recognise.',
            'Vérifiez Réglages → Général → VPN et gestion de l’appareil pour tout profil inconnu.',
          ),
        ),
        CoverageItem(
          'IOS-MAN-SAFETY',
          LText('Sharing & access review', 'Revue des partages et accès'),
          CoverageStatus.unavailable,
          note: LText(
            'Use Safety Check (Settings → Privacy & Security → Safety Check) to review who has access.',
            'Utilisez Contrôle de sécurité (Réglages → Confidentialité et sécurité) pour vérifier qui a accès.',
          ),
        ),
        CoverageItem(
          'MAN-CALLFWD',
          LText('Call forwarding', 'Renvoi d’appel'),
          CoverageStatus.unavailable,
          note: LText(
            'Carrier-side; check with the dialer (*#21#) or Settings → Phone → Call Forwarding.',
            'Côté opérateur ; vérifiez via le composeur (*#21#) ou Réglages → Téléphone → Renvoi d’appel.',
          ),
        ),
      ];
    }
    return const [
      CoverageItem(
        'MAN-CALLFWD',
        LText('Call forwarding', 'Renvoi d’appel'),
        CoverageStatus.unavailable,
        note: LText('Carrier-side; check from Call & Microphone screen (*#21#).', 'Côté opérateur ; vérifiez depuis l’écran Appels & micro (*#21#).'),
      ),
      CoverageItem(
        'MAN-MICUSE',
        LText('Recent microphone use by other apps', 'Usage récent du micro par d’autres apps'),
        CoverageStatus.unavailable,
        note: LText('Only the system Privacy Dashboard can show it.', 'Seul le tableau de bord de confidentialité système peut l’afficher.'),
      ),
    ];
  }

  static String _id(DateTime t) => 'S-${t.millisecondsSinceEpoch.toRadixString(36).toUpperCase()}${Random().nextInt(1 << 16).toRadixString(36).toUpperCase()}';
}
