import 'models.dart';

enum IncidentStatus { newIncident, investigating, confirmed, falsePositive, remediationRecommended, resolved }

class TimelineEvent {
  TimelineEvent(this.at, this.text);
  final DateTime at;
  final LText text;

  Map<String, dynamic> toJson() => {'at': at.toIso8601String(), 'text': text.toJson()};
  factory TimelineEvent.fromJson(Map<String, dynamic> j) => TimelineEvent(DateTime.parse(j['at'] as String), LText.fromJson(j['text']));
}

/// An incident groups observations of the same finding over time.
class Incident {
  Incident({
    required this.id,
    required this.finding,
    required this.firstObserved,
    required this.lastObserved,
    this.status = IncidentStatus.newIncident,
    this.notes = '',
    List<TimelineEvent>? timeline,
  }) : timeline = timeline ?? [];

  final String id;
  Finding finding;
  final DateTime firstObserved;
  DateTime lastObserved;
  IncidentStatus status;
  String notes;
  final List<TimelineEvent> timeline;

  bool get open => status != IncidentStatus.resolved && status != IncidentStatus.falsePositive;

  Map<String, dynamic> toJson() => {
    'id': id,
    'finding': finding.toJson(),
    'firstObserved': firstObserved.toIso8601String(),
    'lastObserved': lastObserved.toIso8601String(),
    'status': status.name,
    'notes': notes,
    'timeline': timeline.map((t) => t.toJson()).toList(),
  };

  factory Incident.fromJson(Map<String, dynamic> j) => Incident(
    id: j['id'] as String,
    finding: Finding.fromJson(Map<String, dynamic>.from(j['finding'] as Map)),
    firstObserved: DateTime.parse(j['firstObserved'] as String),
    lastObserved: DateTime.parse(j['lastObserved'] as String),
    status: enumByName(IncidentStatus.values, j['status'], IncidentStatus.newIncident),
    notes: j['notes'] as String? ?? '',
    timeline: ((j['timeline'] as List?) ?? const []).map((e) => TimelineEvent.fromJson(Map<String, dynamic>.from(e as Map))).toList(),
  );
}

/// Creates/updates incidents from scan findings. Pure logic, unit-tested.
class IncidentManager {
  /// Only findings worth tracking become incidents.
  static bool qualifies(Finding f) => f.severity.index >= Severity.medium.index && f.classification != Classification.informational;

  /// Returns the ids of incidents that are new or re-opened (for notifications).
  static Set<String> ingest(Map<String, Incident> incidents, List<Finding> findings, DateTime now) {
    final changed = <String>{};
    final seen = <String>{};
    for (final f in findings.where(qualifies)) {
      final id = 'INC-${f.id.substring(2)}';
      seen.add(id);
      final existing = incidents[id];
      if (existing == null) {
        incidents[id] = Incident(
          id: id,
          finding: f,
          firstObserved: now,
          lastObserved: now,
          timeline: [TimelineEvent(now, LText('Detected by ${f.ruleId}', 'Détecté par ${f.ruleId}'))],
        );
        changed.add(id);
      } else {
        existing
          ..finding = f
          ..lastObserved = now;
        if (existing.status == IncidentStatus.resolved) {
          existing.status = IncidentStatus.newIncident;
          existing.timeline.add(TimelineEvent(now, const LText('Observed again after resolution — reopened', 'Observé de nouveau après résolution — rouvert')));
          changed.add(id);
        }
        // False positives stay closed: the user's verdict is respected.
      }
    }
    // Indicators that disappeared are noted but not auto-resolved: the user decides.
    for (final inc in incidents.values) {
      if (inc.open && !seen.contains(inc.id) && inc.finding.platform != DevicePlatform.unknown && !inc.id.contains('APK')) {
        final last = inc.timeline.isEmpty ? null : inc.timeline.last;
        if (last == null || !last.text.en.startsWith('Not observed')) {
          inc.timeline.add(TimelineEvent(now, const LText('Not observed in latest full scan', 'Non observé lors du dernier scan complet')));
        }
      }
    }
    return changed;
  }

  static void setStatus(Incident inc, IncidentStatus s, DateTime now) {
    if (inc.status == s) return;
    inc.status = s;
    inc.timeline.add(TimelineEvent(now, LText('Status → ${s.name}', 'Statut → ${s.name}')));
    inc.finding.status = switch (s) {
      IncidentStatus.resolved => RemediationStatus.resolved,
      IncidentStatus.falsePositive => RemediationStatus.falsePositive,
      IncidentStatus.investigating || IncidentStatus.remediationRecommended => RemediationStatus.inProgress,
      _ => RemediationStatus.open,
    };
  }

  /// Human-readable, shareable report. Contains no data beyond what is shown in the app.
  static String exportMarkdown(Incident inc, String lang) {
    final f = inc.finding;
    final b = StringBuffer()
      ..writeln('# ${inc.id} — ${f.title.of(lang)}')
      ..writeln()
      ..writeln('| | |')
      ..writeln('|---|---|')
      ..writeln('| Status | ${inc.status.name} |')
      ..writeln('| Severity | ${f.severity.name} |')
      ..writeln('| Confidence | ${f.confidence.name} |')
      ..writeln('| Classification | ${f.classification.name} |')
      ..writeln('| Component | ${f.componentLabel ?? f.component ?? '-'} |')
      ..writeln('| Detection source | ${f.ruleId} v${f.ruleVersion} — ${f.method.of(lang)} |')
      ..writeln('| First observed | ${inc.firstObserved.toIso8601String()} |')
      ..writeln('| Last observed | ${inc.lastObserved.toIso8601String()} |')
      ..writeln('| Platform | ${f.platform.name} |')
      ..writeln()
      ..writeln('## Description')
      ..writeln(f.description.of(lang))
      ..writeln()
      ..writeln('## Evidence');
    f.evidence.forEach((k, v) => b.writeln('- **$k**: $v'));
    b
      ..writeln()
      ..writeln('## Limitations')
      ..writeln(f.limitations.of(lang))
      ..writeln()
      ..writeln('## Remediation');
    for (final r in f.remediation) {
      b.writeln('- ${r.label.of(lang)}');
    }
    b
      ..writeln()
      ..writeln('## Timeline');
    for (final t in inc.timeline) {
      b.writeln('- ${t.at.toIso8601String()} — ${t.text.of(lang)}');
    }
    if (inc.notes.isNotEmpty) {
      b
        ..writeln()
        ..writeln('## Resolution notes')
        ..writeln(inc.notes);
    }
    b
      ..writeln()
      ..writeln('_Generated by Sentinel Mobile SOC. Heuristic findings are indicators, not proof of compromise._');
    return b.toString();
  }
}
