import '../core/incident.dart';
import '../core/models.dart';
import '../core/settings.dart';
import '../detection/rule_pack.dart';
import '../engine/network_probe.dart';
import '../engine/scan_engine.dart';
import 'notifier.dart';
import 'repository.dart';

/// Runs a scan and applies its side effects (history, incidents, feedback,
/// notifications). Shared by the UI and the background scheduler.
class ScanCoordinator {
  ScanCoordinator({required this.repo, required this.source, this.notifier, ScanEngine? engine})
      : engine = engine ?? ScanEngine(networkProbe: NetworkProbe());

  final Repository repo;
  final SnapshotSource source;
  final Notifier? notifier;
  final ScanEngine engine;

  Future<ScanReport> run({
    required ScanMode mode,
    required RulePack pack,
    required AppSettings settings,
    bool background = false,
    void Function(ScanProgress)? onProgress,
  }) async {
    final report = await engine.run(
      source: source,
      pack: pack,
      mode: mode,
      background: background,
      networkChecksEnabled: settings.networkChecks,
      onProgress: onProgress,
    );

    // Carry the user's false-positive verdicts forward.
    final feedback = await repo.loadFeedback();
    for (final f in report.findings) {
      if (feedback.containsKey(f.id)) f.status = RemediationStatus.falsePositive;
    }
    await repo.addReport(report, retentionDays: settings.retentionDays);

    final incidents = await repo.loadIncidents();
    for (final inc in incidents.values) {
      if (inc.status == IncidentStatus.falsePositive) feedback[inc.finding.id] = 'incident marked false positive';
    }
    await repo.saveFeedback(feedback);
    IncidentManager.ingest(incidents, report.findings.where((f) => f.isActive).toList(), report.finishedAt);
    await repo.saveIncidents(incidents);

    if (settings.notificationsEnabled && notifier != null) {
      final notified = await repo.loadNotified();
      final toNotify = NotificationPolicy.select(report.findings, notified, highOnly: settings.notifyHighOnly);
      await repo.saveNotified(notified);
      await notifier!.notifyFindings(toNotify, settings.languageCode ?? 'en');
    }
    return report;
  }
}
