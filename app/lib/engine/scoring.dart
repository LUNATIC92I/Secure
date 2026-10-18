import 'dart:math';

import '../core/models.dart';

enum Posture { strong, fair, atRisk, critical, unknown }

/// Device security score; methodology documented in docs/SCORING.md.
///
/// score = 100 − Σ penalty, penalty = severity.weight × confidence.factor × classFactor,
/// with per-category caps so a single noisy area cannot zero the score on its own.
/// Coverage is reported alongside and never inflates the score.
class SecurityScore {
  SecurityScore._(this.score, this.posture, this.coverage, this.penalties, this.activeFindings);

  final int score;
  final Posture posture;

  /// Fraction (0-1) of applicable checks that could actually run.
  final double coverage;
  final Map<FindingCategory, double> penalties;
  final int activeFindings;

  static const classFactor = {
    Classification.confirmedMalicious: 1.5,
    Classification.suspicious: 1.0,
    Classification.exposure: 1.0,
    Classification.unverified: 0.5,
    Classification.informational: 0.0,
  };

  static const categoryCap = 45.0;

  static SecurityScore compute(List<Finding> findings, List<CoverageItem> coverageItems) {
    final active = findings.where((f) => f.isActive).toList();
    final penalties = <FindingCategory, double>{};
    for (final f in active) {
      final p = f.severity.weight * f.confidence.factor * classFactor[f.classification]!;
      penalties[f.category] = min(categoryCap, (penalties[f.category] ?? 0) + p);
    }
    final total = penalties.values.fold<double>(0, (a, b) => a + b);
    final score = max(0, 100 - total.round());

    final applicable = coverageItems.where((c) => c.status != CoverageStatus.notApplicable).toList();
    final checked = applicable.where((c) => c.status == CoverageStatus.checked).length;
    final coverage = applicable.isEmpty ? 0.0 : checked / applicable.length;

    Posture posture;
    final hasCriticalConfirmed = active.any((f) => f.classification == Classification.confirmedMalicious || f.severity == Severity.critical);
    final hasHigh = active.any((f) => f.severity == Severity.high && f.classification != Classification.informational);
    if (applicable.isEmpty) {
      posture = Posture.unknown;
    } else if (hasCriticalConfirmed || score < 40) {
      posture = Posture.critical;
    } else if (hasHigh || score < 70) {
      posture = Posture.atRisk;
    } else if (score < 85) {
      posture = Posture.fair;
    } else {
      posture = Posture.strong;
    }
    return SecurityScore._(score, posture, coverage, penalties, active.length);
  }
}
