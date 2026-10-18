import 'package:flutter_test/flutter_test.dart';
import 'package:sentinel_mobile_soc/core/incident.dart';
import 'package:sentinel_mobile_soc/core/models.dart';
import 'package:sentinel_mobile_soc/engine/tracker_assessor.dart';
import 'package:sentinel_mobile_soc/services/notifier.dart';

import 'engine_scoring_test.dart' show f;

void main() {
  final t0 = DateTime(2026, 10, 18, 9);

  group('incidents', () {
    test('only medium+ non-informational findings become incidents', () {
      final m = <String, Incident>{};
      final changed = IncidentManager.ingest(m, [
        f(Severity.high, Confidence.high, Classification.exposure, id: 'A'),
        f(Severity.low, Confidence.high, Classification.exposure, id: 'B'),
        f(Severity.high, Confidence.high, Classification.informational, id: 'C'),
      ], t0);
      expect(m, hasLength(1));
      expect(changed, hasLength(1));
      expect(m.values.single.status, IncidentStatus.newIncident);
    });

    test('resolved incident reopens when observed again; false positive stays closed', () {
      final m = <String, Incident>{};
      final a = f(Severity.high, Confidence.high, Classification.suspicious, id: 'A');
      final b = f(Severity.high, Confidence.high, Classification.suspicious, id: 'B');
      IncidentManager.ingest(m, [a, b], t0);
      final ia = m.values.firstWhere((i) => i.finding.ruleId == 'A');
      final ib = m.values.firstWhere((i) => i.finding.ruleId == 'B');
      IncidentManager.setStatus(ia, IncidentStatus.resolved, t0);
      IncidentManager.setStatus(ib, IncidentStatus.falsePositive, t0);
      final changed = IncidentManager.ingest(m, [a, b], t0.add(const Duration(days: 1)));
      expect(ia.status, IncidentStatus.newIncident);
      expect(ib.status, IncidentStatus.falsePositive);
      expect(changed, {ia.id});
      expect(ia.lastObserved, t0.add(const Duration(days: 1)));
    });

    test('status change is recorded in the timeline and mapped to the finding', () {
      final m = <String, Incident>{};
      IncidentManager.ingest(m, [f(Severity.critical, Confidence.high, Classification.confirmedMalicious)], t0);
      final i = m.values.single;
      IncidentManager.setStatus(i, IncidentStatus.investigating, t0);
      expect(i.timeline.last.text.en, contains('investigating'));
      expect(i.finding.status, RemediationStatus.inProgress);
    });

    test('markdown export contains required fields in both languages', () {
      final m = <String, Incident>{};
      IncidentManager.ingest(m, [f(Severity.high, Confidence.medium, Classification.suspicious)], t0);
      final i = m.values.single..notes = 'checked with owner';
      for (final lang in ['en', 'fr']) {
        final md = IncidentManager.exportMarkdown(i, lang);
        expect(md, allOf(contains(i.id), contains('Severity'), contains('Confidence'), contains('Timeline'), contains('checked with owner')));
      }
    });

    test('JSON round-trip', () {
      final m = <String, Incident>{};
      IncidentManager.ingest(m, [f(Severity.high, Confidence.high, Classification.exposure)], t0);
      final back = Incident.fromJson(m.values.single.toJson());
      expect(back.id, m.values.single.id);
      expect(back.timeline, hasLength(1));
    });
  });

  group('notification policy', () {
    test('deduplicates unchanged findings and re-alerts on escalation', () {
      final notified = <String, String>{};
      final a = f(Severity.high, Confidence.high, Classification.suspicious, id: 'A');
      expect(NotificationPolicy.select([a], notified, highOnly: true), hasLength(1));
      expect(NotificationPolicy.select([a], notified, highOnly: true), isEmpty);
      final escalated = Finding.fromJson(a.toJson()..['severity'] = 'critical');
      expect(NotificationPolicy.select([escalated], notified, highOnly: true), hasLength(1));
    });

    test('respects threshold, informational and false positives', () {
      final notified = <String, String>{};
      final med = f(Severity.medium, Confidence.high, Classification.exposure, id: 'M');
      final info = f(Severity.critical, Confidence.high, Classification.informational, id: 'I');
      final fp = f(Severity.critical, Confidence.high, Classification.suspicious, id: 'P')..status = RemediationStatus.falsePositive;
      expect(NotificationPolicy.select([med, info, fp], notified, highOnly: true), isEmpty);
      expect(NotificationPolicy.select([med], notified, highOnly: false), hasLength(1));
    });
  });

  group('tracker assessment', () {
    test('single sighting is informational; persistent sighting is medium/unverified', () {
      var h = TrackerAssessor.merge([], [
        {'address': 'AA', 'kind': 'apple_findmy', 'rssi': -60}
      ], t0);
      var out = TrackerAssessor.assess(h, {'AA'}, DevicePlatform.android, t0);
      expect(out.single.severity, Severity.informational);

      final later = t0.add(const Duration(minutes: 45));
      h = TrackerAssessor.merge(h, [
        {'address': 'AA', 'kind': 'apple_findmy', 'rssi': -55}
      ], later);
      out = TrackerAssessor.assess(h, {'AA'}, DevicePlatform.android, later);
      expect(out.single.severity, Severity.medium);
      expect(out.single.classification, Classification.unverified, reason: 'never claims confirmed tracking');
    });

    test('old sightings expire', () {
      final h = TrackerAssessor.merge([], [
        {'address': 'AA', 'kind': 'tile'}
      ], t0);
      expect(TrackerAssessor.merge(h, [], t0.add(const Duration(days: 4))), isEmpty);
    });
  });
}
