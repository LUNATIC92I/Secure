import 'dart:convert';

import 'package:crypto/crypto.dart';

/// Bilingual text used by detection rules so findings can be rendered in the
/// user's language and exported reports stay readable.
class LText {
  const LText(this.en, this.fr);

  final String en;
  final String fr;

  String of(String languageCode) => languageCode == 'fr' ? fr : en;

  Map<String, String> toJson() => {'en': en, 'fr': fr};

  factory LText.fromJson(Object? json) {
    if (json is Map) return LText('${json['en'] ?? ''}', '${json['fr'] ?? json['en'] ?? ''}');
    final s = json?.toString() ?? '';
    return LText(s, s);
  }
}

enum DevicePlatform { android, ios, unknown }

/// Severity is about impact if the indicator is real. Its weight feeds the score
/// (see docs/SCORING.md); informational findings never reduce the score.
enum Severity {
  informational(0),
  low(2),
  medium(6),
  high(15),
  critical(30);

  const Severity(this.weight);
  final int weight;
}

/// How strongly the evidence supports the finding.
enum Confidence {
  low(0.4),
  medium(0.7),
  high(1.0);

  const Confidence(this.factor);
  final double factor;
}

/// Keeps "we matched a known bad indicator" separate from "this looks risky".
enum Classification {
  /// Exact match against a curated indicator of compromise (hash / signing cert).
  confirmedMalicious,

  /// Combination of behaviours associated with malware or stalkerware.
  suspicious,

  /// A configuration weakness that increases attack surface.
  exposure,

  /// Something the user should verify; no conclusion possible from the device.
  unverified,

  informational,
}

enum FindingCategory {
  malware,
  stalkerware,
  permissions,
  configuration,
  integrity,
  network,
  privacy,
  tracking,
  microphone,
  phishing,
  apk,
}

enum RemediationStatus { open, inProgress, resolved, accepted, falsePositive }

/// A safe, user-driven remediation step. Actions only open system UI.
class RemediationStep {
  const RemediationStep(this.label, {this.action, this.target, this.package});

  final LText label;

  /// One of: openSettings, uninstall, dial, openUrl. Null for advice-only steps.
  final String? action;
  final String? target;
  final String? package;

  Map<String, dynamic> toJson() => {
        'label': label.toJson(),
        if (action != null) 'action': action,
        if (target != null) 'target': target,
        if (package != null) 'package': package,
      };

  factory RemediationStep.fromJson(Map<String, dynamic> j) => RemediationStep(
        LText.fromJson(j['label']),
        action: j['action'] as String?,
        target: j['target'] as String?,
        package: j['package'] as String?,
      );
}

class Finding {
  Finding({
    required this.ruleId,
    required this.ruleVersion,
    required this.platform,
    required this.title,
    required this.description,
    required this.severity,
    required this.confidence,
    required this.classification,
    required this.category,
    required this.method,
    required this.limitations,
    this.component,
    this.componentLabel,
    Map<String, String>? evidence,
    List<RemediationStep>? remediation,
    DateTime? detectedAt,
    this.status = RemediationStatus.open,
    String? id,
  })  : evidence = evidence ?? const {},
        remediation = remediation ?? const [],
        detectedAt = detectedAt ?? DateTime.now(),
        id = id ?? fingerprintFor(ruleId, component);

  /// Stable across scans for the same rule + component, which lets the app
  /// deduplicate notifications and carry user feedback forward.
  final String id;
  final String ruleId;
  final int ruleVersion;
  final DateTime detectedAt;
  final DevicePlatform platform;
  final String? component;
  final String? componentLabel;
  final LText title;
  final LText description;
  final Severity severity;
  final Confidence confidence;
  final Classification classification;
  final FindingCategory category;
  final Map<String, String> evidence;
  final LText method;
  final LText limitations;
  final List<RemediationStep> remediation;
  RemediationStatus status;

  bool get isActive => status != RemediationStatus.resolved && status != RemediationStatus.falsePositive;

  static String fingerprintFor(String ruleId, String? component) {
    final digest = sha256.convert(utf8.encode('$ruleId|${component ?? '-'}'));
    return 'F-${digest.toString().substring(0, 12).toUpperCase()}';
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'ruleId': ruleId,
        'ruleVersion': ruleVersion,
        'detectedAt': detectedAt.toIso8601String(),
        'platform': platform.name,
        'component': component,
        'componentLabel': componentLabel,
        'title': title.toJson(),
        'description': description.toJson(),
        'severity': severity.name,
        'confidence': confidence.name,
        'classification': classification.name,
        'category': category.name,
        'evidence': evidence,
        'method': method.toJson(),
        'limitations': limitations.toJson(),
        'remediation': remediation.map((r) => r.toJson()).toList(),
        'status': status.name,
      };

  factory Finding.fromJson(Map<String, dynamic> j) => Finding(
        id: j['id'] as String,
        ruleId: j['ruleId'] as String,
        ruleVersion: (j['ruleVersion'] as num?)?.toInt() ?? 1,
        detectedAt: DateTime.parse(j['detectedAt'] as String),
        platform: _enum(DevicePlatform.values, j['platform'], DevicePlatform.unknown),
        component: j['component'] as String?,
        componentLabel: j['componentLabel'] as String?,
        title: LText.fromJson(j['title']),
        description: LText.fromJson(j['description']),
        severity: _enum(Severity.values, j['severity'], Severity.informational),
        confidence: _enum(Confidence.values, j['confidence'], Confidence.low),
        classification: _enum(Classification.values, j['classification'], Classification.unverified),
        category: _enum(FindingCategory.values, j['category'], FindingCategory.configuration),
        evidence: (j['evidence'] as Map?)?.map((k, v) => MapEntry('$k', '$v')) ?? const {},
        method: LText.fromJson(j['method']),
        limitations: LText.fromJson(j['limitations']),
        remediation: ((j['remediation'] as List?) ?? const [])
            .map((e) => RemediationStep.fromJson(Map<String, dynamic>.from(e as Map)))
            .toList(),
        status: _enum(RemediationStatus.values, j['status'], RemediationStatus.open),
      );
}

T _enum<T extends Enum>(List<T> values, Object? name, T fallback) =>
    values.firstWhere((v) => v.name == name, orElse: () => fallback);

T enumByName<T extends Enum>(List<T> values, Object? name, T fallback) => _enum(values, name, fallback);

/// Whether a given security surface was actually examined.
enum CoverageStatus { checked, unavailable, permissionRequired, notApplicable, error }

class CoverageItem {
  const CoverageItem(this.checkId, this.label, this.status, {this.note});

  final String checkId;
  final LText label;
  final CoverageStatus status;
  final LText? note;

  Map<String, dynamic> toJson() => {
        'checkId': checkId,
        'label': label.toJson(),
        'status': status.name,
        if (note != null) 'note': note!.toJson(),
      };

  factory CoverageItem.fromJson(Map<String, dynamic> j) => CoverageItem(
        j['checkId'] as String,
        LText.fromJson(j['label']),
        _enum(CoverageStatus.values, j['status'], CoverageStatus.unavailable),
        note: j['note'] == null ? null : LText.fromJson(j['note']),
      );
}

enum ScanMode { quick, comprehensive, daily, apk, url, tracker }

class ScanReport {
  ScanReport({
    required this.id,
    required this.mode,
    required this.platform,
    required this.startedAt,
    required this.finishedAt,
    required this.findings,
    required this.coverage,
    this.errors = const [],
    this.rulePackVersion,
    this.appsAnalyzed = 0,
    this.background = false,
  });

  final String id;
  final ScanMode mode;
  final DevicePlatform platform;
  final DateTime startedAt;
  final DateTime finishedAt;
  final List<Finding> findings;
  final List<CoverageItem> coverage;
  final List<String> errors;
  final int? rulePackVersion;
  final int appsAnalyzed;

  /// True when produced by the OS background scheduler rather than the user.
  final bool background;

  Map<String, dynamic> toJson() => {
        'id': id,
        'mode': mode.name,
        'platform': platform.name,
        'startedAt': startedAt.toIso8601String(),
        'finishedAt': finishedAt.toIso8601String(),
        'findings': findings.map((f) => f.toJson()).toList(),
        'coverage': coverage.map((c) => c.toJson()).toList(),
        'errors': errors,
        'rulePackVersion': rulePackVersion,
        'appsAnalyzed': appsAnalyzed,
        'background': background,
      };

  factory ScanReport.fromJson(Map<String, dynamic> j) => ScanReport(
        id: j['id'] as String,
        mode: _enum(ScanMode.values, j['mode'], ScanMode.quick),
        platform: _enum(DevicePlatform.values, j['platform'], DevicePlatform.unknown),
        startedAt: DateTime.parse(j['startedAt'] as String),
        finishedAt: DateTime.parse(j['finishedAt'] as String),
        findings: ((j['findings'] as List?) ?? const [])
            .map((e) => Finding.fromJson(Map<String, dynamic>.from(e as Map)))
            .toList(),
        coverage: ((j['coverage'] as List?) ?? const [])
            .map((e) => CoverageItem.fromJson(Map<String, dynamic>.from(e as Map)))
            .toList(),
        errors: ((j['errors'] as List?) ?? const []).map((e) => '$e').toList(),
        rulePackVersion: (j['rulePackVersion'] as num?)?.toInt(),
        appsAnalyzed: (j['appsAnalyzed'] as num?)?.toInt() ?? 0,
        background: j['background'] == true,
      );
}
