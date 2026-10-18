import '../core/incident.dart';
import '../core/models.dart';
import '../core/settings.dart';
import '../engine/tracker_assessor.dart';
import 'secure_store.dart';

/// All persisted state, encrypted at rest through [SecureStore].
class Repository {
  Repository(this.store);

  final SecureStore store;

  static const _reports = 'reports';
  static const _incidents = 'incidents';
  static const _settings = 'settings';
  static const _notified = 'notified';
  static const _trackers = 'trackers';
  static const _feedback = 'feedback';
  static const _rulepack = 'rulepack';

  Future<AppSettings> loadSettings() async {
    final j = await store.read(_settings);
    return j is Map ? AppSettings.fromJson(Map<String, dynamic>.from(j)) : AppSettings();
  }

  Future<void> saveSettings(AppSettings s) => store.write(_settings, s.toJson());

  Future<List<ScanReport>> loadReports() async {
    final j = await store.read(_reports);
    if (j is! List) return [];
    return j.map((e) => ScanReport.fromJson(Map<String, dynamic>.from(e as Map))).toList();
  }

  /// Stores newest first and applies the retention window.
  Future<List<ScanReport>> addReport(ScanReport r, {required int retentionDays}) async {
    final all = [r, ...await loadReports()];
    final cutoff = DateTime.now().subtract(Duration(days: retentionDays));
    final kept = all.where((x) => x.finishedAt.isAfter(cutoff)).take(200).toList();
    await store.write(_reports, kept.map((e) => e.toJson()).toList());
    return kept;
  }

  Future<Map<String, Incident>> loadIncidents() async {
    final j = await store.read(_incidents);
    if (j is! List) return {};
    final list = j.map((e) => Incident.fromJson(Map<String, dynamic>.from(e as Map)));
    return {for (final i in list) i.id: i};
  }

  Future<void> saveIncidents(Map<String, Incident> m) => store.write(_incidents, m.values.map((e) => e.toJson()).toList());

  /// Finding fingerprint → last severity notified, for notification deduplication.
  Future<Map<String, String>> loadNotified() async {
    final j = await store.read(_notified);
    return j is Map ? j.map((k, v) => MapEntry('$k', '$v')) : {};
  }

  Future<void> saveNotified(Map<String, String> m) => store.write(_notified, m);

  Future<List<TrackerSighting>> loadTrackers() async {
    final j = await store.read(_trackers);
    if (j is! List) return [];
    return j.map((e) => TrackerSighting.fromJson(Map<String, dynamic>.from(e as Map))).toList();
  }

  Future<void> saveTrackers(List<TrackerSighting> l) => store.write(_trackers, l.map((e) => e.toJson()).toList());

  /// Finding id → false-positive note (kept so the same finding stays dismissed).
  Future<Map<String, String>> loadFeedback() async {
    final j = await store.read(_feedback);
    return j is Map ? j.map((k, v) => MapEntry('$k', '$v')) : {};
  }

  Future<void> saveFeedback(Map<String, String> m) => store.write(_feedback, m);

  /// Downloaded rule pack (body + signature); re-verified at every load.
  Future<(String, String)?> loadRulePack() async {
    final j = await store.read(_rulepack);
    if (j is! Map) return null;
    return ('${j['body']}', '${j['sig']}');
  }

  Future<void> saveRulePack(String body, String sig) => store.write(_rulepack, {'body': body, 'sig': sig});

  Future<void> deleteHistory() async {
    await store.delete(_reports);
    await store.delete(_incidents);
    await store.delete(_notified);
    await store.delete(_trackers);
  }

  Future<void> wipeAll() => store.wipe();
}
