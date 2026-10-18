import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:sentinel_native/sentinel_native.dart';

import '../core/incident.dart';
import '../core/models.dart';
import '../core/settings.dart';
import '../core/snapshot.dart';
import '../detection/rule_pack.dart';
import '../engine/apk_analyzer.dart';
import '../engine/scan_engine.dart';
import '../engine/scoring.dart';
import '../engine/tracker_assessor.dart';
import '../engine/url_analyzer.dart';
import '../intel/threat_intel.dart';
import '../services/background.dart';
import '../services/notifier.dart';
import '../services/platform_source.dart';
import '../services/repository.dart';
import '../services/rule_pack_loader.dart';
import '../services/scan_coordinator.dart';

class AppState extends ChangeNotifier {
  AppState({required this.repo, required this.native, SnapshotSource? source, Notifier? notifier, RulePackLoader? loader})
    : source = source ?? PlatformSnapshotSource(native),
      notifier = notifier ?? Notifier(),
      loader = loader ?? RulePackLoader(repo);

  final Repository repo;
  final SentinelNative native;
  final SnapshotSource source;
  final Notifier notifier;
  final RulePackLoader loader;

  AppSettings settings = AppSettings();
  RulePack pack = RulePack.empty();
  List<ScanReport> reports = [];
  Map<String, Incident> incidents = {};
  List<TrackerSighting> trackers = [];
  Map<String, dynamic> platformInfo = {};
  bool loaded = false;
  String? loadError;

  ScanProgress? progress;
  ScanMode? scanningMode;
  late IntelService intel = _buildIntel();

  /// Pending URL shared into the app (share sheet / URL scheme).
  String? sharedUrl;

  DevicePlatform get platform => Platform.isAndroid ? DevicePlatform.android : (Platform.isIOS ? DevicePlatform.ios : DevicePlatform.unknown);
  String get lang => settings.languageCode ?? PlatformDispatcher.instance.locale.languageCode;
  bool get scanning => scanningMode != null;

  ScanReport? get lastFullReport => reports.where((r) => r.mode != ScanMode.apk && r.mode != ScanMode.url && r.mode != ScanMode.tracker).firstOrNull;

  /// Score uses the latest device scan plus the current incident decisions.
  SecurityScore? get score {
    final r = lastFullReport;
    if (r == null) return null;
    return SecurityScore.compute(r.findings, r.coverage);
  }

  List<Finding> get activeFindings => lastFullReport?.findings.where((f) => f.isActive).toList() ?? const [];

  /// True when daily assessment is on but no scan completed in the last 36 hours.
  bool get assessmentOverdue {
    if (!settings.dailyAssessment) return false;
    final r = lastFullReport;
    return r == null || DateTime.now().difference(r.finishedAt) > const Duration(hours: 36);
  }

  Future<void> init() async {
    try {
      settings = await repo.loadSettings();
      pack = await loader.load(minimumVersion: settings.minRulePackVersion);
      reports = await repo.loadReports();
      incidents = await repo.loadIncidents();
      trackers = await repo.loadTrackers();
      intel = _buildIntel();
      try {
        platformInfo = await native.platformInfo();
      } catch (_) {}
      loadError = loader.lastError;
    } catch (e) {
      loadError = '$e';
    }
    loaded = true;
    native.onSharedText.listen((_) => _pullShared());
    unawaited(_pullShared());
    notifyListeners();
  }

  Future<void> _pullShared() async {
    try {
      final text = await native.consumeSharedText();
      if (text != null) {
        sharedUrl = UrlAnalyzer.extractUrl(text) ?? text;
        notifyListeners();
      }
    } catch (_) {}
  }

  void consumeSharedUrl() => sharedUrl = null;

  IntelService _buildIntel() {
    final providers = <ThreatIntelProvider>[LocalRulePackProvider(pack)];
    if (settings.backendConfigured) {
      providers.add(BackendProvider(baseUrl: Uri.parse(settings.backendUrl), token: settings.backendToken, sendFullUrls: settings.cloudFullUrls));
    }
    return IntelService(providers: providers);
  }

  Future<void> updateSettings(void Function(AppSettings) change) async {
    final wasDaily = settings.dailyAssessment;
    change(settings);
    await repo.saveSettings(settings);
    intel = _buildIntel();
    if (wasDaily != settings.dailyAssessment) {
      try {
        settings.dailyAssessment ? await BackgroundScheduler.enable() : await BackgroundScheduler.disable();
      } catch (_) {}
    }
    notifyListeners();
  }

  Future<ScanReport?> runScan(ScanMode mode) async {
    if (scanning) return null;
    scanningMode = mode;
    progress = const ScanProgress(0, LText('Starting', 'Démarrage'));
    notifyListeners();
    try {
      final report = await ScanCoordinator(repo: repo, source: source, notifier: notifier).run(
        mode: mode,
        pack: pack,
        settings: settings,
        onProgress: (p) {
          progress = p;
          notifyListeners();
        },
      );
      reports = await repo.loadReports();
      incidents = await repo.loadIncidents();
      return report;
    } finally {
      scanningMode = null;
      progress = null;
      notifyListeners();
    }
  }

  Future<void> markFalsePositive(Finding f, String note) async {
    final fb = await repo.loadFeedback();
    fb[f.id] = note.isEmpty ? 'user feedback' : note;
    await repo.saveFeedback(fb);
    f.status = RemediationStatus.falsePositive;
    final inc = incidents['INC-${f.id.substring(2)}'];
    if (inc != null) {
      IncidentManager.setStatus(inc, IncidentStatus.falsePositive, DateTime.now());
      await repo.saveIncidents(incidents);
    }
    await _persistReports();
    notifyListeners();
  }

  Future<void> setFindingStatus(Finding f, RemediationStatus s) async {
    f.status = s;
    if (s != RemediationStatus.falsePositive) {
      final fb = await repo.loadFeedback();
      if (fb.remove(f.id) != null) await repo.saveFeedback(fb);
    }
    await _persistReports();
    notifyListeners();
  }

  Future<void> _persistReports() async {
    await repo.store.write('reports', reports.map((r) => r.toJson()).toList());
  }

  Future<void> setIncidentStatus(Incident inc, IncidentStatus s, {String? notes}) async {
    IncidentManager.setStatus(inc, s, DateTime.now());
    if (notes != null) inc.notes = notes;
    await repo.saveIncidents(incidents);
    notifyListeners();
  }

  /// Executes a remediation step. Every action opens system UI; nothing is changed silently.
  Future<bool> perform(RemediationStep step) async {
    switch (step.action) {
      case 'openSettings':
        return native.openSettings(step.target ?? 'settings', package: step.package);
      case 'uninstall':
        return step.package != null && await native.requestUninstall(step.package!);
      case 'dial':
        return step.target != null && await native.openDialer(step.target!);
      default:
        return false;
    }
  }

  // ---------------------------------------------------------------- feature modules

  Future<List<AppInfo>> loadApps() async {
    final inv = await native.installedApps();
    return ((inv['apps'] as List?) ?? const []).map((e) => AppInfo.fromMap(Map<String, dynamic>.from(e as Map))).toList();
  }

  Future<DeviceSnapshot> snapshot({bool apps = false}) => source.collect(includeApps: apps);

  Future<(ApkReport, List<IntelVerdict>)?> analyseApk() async {
    final picked = await native.pickApk();
    if (picked == null) return null;
    final path = picked['path'] as String;
    try {
      final meta = await native.analyzeApk(path);
      final yara = pack.yaraSource;
      final report = await ApkAnalyzer(pack).analyse(path: path, fileName: '${picked['displayName']}', native: meta, yaraSource: yara);
      final verdicts = await intel.lookup(IntelKind.fileHash, report.sha256, allowRemote: settings.cloudIntel);
      final scan = ScanReport(
        id: 'APK-${report.sha256.substring(0, 10)}-${DateTime.now().millisecondsSinceEpoch}',
        mode: ScanMode.apk,
        platform: platform,
        startedAt: DateTime.now(),
        finishedAt: DateTime.now(),
        findings: report.findings,
        coverage: const [],
        rulePackVersion: pack.version,
      );
      reports = await repo.addReport(scan, retentionDays: settings.retentionDays);
      IncidentManager.ingest(incidents, report.findings, DateTime.now());
      await repo.saveIncidents(incidents);
      notifyListeners();
      return (report, verdicts);
    } finally {
      // The copied APK lives in the app cache only for the duration of the analysis.
      try {
        await File(path).delete();
      } catch (_) {}
    }
  }

  Future<(UrlAnalysis, List<IntelVerdict>)> analyseUrl(String raw, {bool followRedirects = false}) async {
    final analyzer = UrlAnalyzer(pack);
    var a = analyzer.analyse(raw);
    if (followRedirects && a.uri != null && (a.uri!.scheme == 'http' || a.uri!.scheme == 'https')) {
      final hops = await UrlAnalyzer.followRedirects(a.uri!);
      a = a.withRedirects(hops, analyzer.analyse);
    }
    final verdicts = a.uri == null ? <IntelVerdict>[] : await intel.lookup(IntelKind.url, a.uri.toString(), allowRemote: settings.cloudIntel);
    if (a.verdict == UrlVerdict.knownMalicious || a.verdict == UrlVerdict.highRisk || verdicts.any((v) => v.status == IntelStatus.malicious)) {
      final f = Finding(
        ruleId: 'PHI-001',
        ruleVersion: 1,
        platform: platform,
        component: a.registrableDomain,
        componentLabel: a.displayHost,
        title: LText('Dangerous link: ${a.displayHost}', 'Lien dangereux : ${a.displayHost}'),
        description: LText(
          'Checked link scored ${a.score}/100 on phishing heuristics.',
          'Le lien vérifié obtient ${a.score}/100 aux heuristiques d’hameçonnage.',
        ),
        severity: a.verdict == UrlVerdict.knownMalicious ? Severity.high : Severity.medium,
        confidence: a.verdict == UrlVerdict.knownMalicious ? Confidence.high : Confidence.medium,
        classification: a.verdict == UrlVerdict.knownMalicious ? Classification.confirmedMalicious : Classification.suspicious,
        category: FindingCategory.phishing,
        method: const LText('URL heuristics + threat intelligence', 'Heuristiques d’URL + renseignement sur les menaces'),
        limitations: const LText('A clean result does not guarantee a link is safe.', 'Un résultat propre ne garantit pas qu’un lien est sûr.'),
        evidence: {'url': a.input, for (final i in a.indicators.take(6)) i.id: i.label.en},
        remediation: const [
          RemediationStep(
            LText(
              'Do not enter credentials on this page. If you already did, change the password from a trusted device.',
              'Ne saisissez pas d’identifiants. Si c’est déjà fait, changez le mot de passe depuis un appareil de confiance.',
            ),
          ),
        ],
      );
      final scan = ScanReport(
        id: 'URL-${DateTime.now().millisecondsSinceEpoch}',
        mode: ScanMode.url,
        platform: platform,
        startedAt: DateTime.now(),
        finishedAt: DateTime.now(),
        findings: [f],
        coverage: const [],
        rulePackVersion: pack.version,
      );
      reports = await repo.addReport(scan, retentionDays: settings.retentionDays);
      notifyListeners();
    }
    return (a, verdicts);
  }

  Future<(String status, List<Finding>)> scanTrackers() async {
    final perm = await native.requestPermission('bluetoothScan');
    if (perm != 'granted' && perm != 'notRequired') return ('permissionDenied', <Finding>[]);
    final res = await native.bleTrackerScan(seconds: 12);
    final status = '${res['status']}';
    if (status != 'ok') return (status, <Finding>[]);
    final devices = ((res['devices'] as List?) ?? const []).map((e) => Map<String, dynamic>.from(e as Map)).toList();
    final now = DateTime.now();
    trackers = TrackerAssessor.merge(trackers, devices, now);
    await repo.saveTrackers(trackers);
    final findings = TrackerAssessor.assess(trackers, devices.map((d) => '${d['address']}').toSet(), platform, now);
    reports = await repo.addReport(
      ScanReport(
        id: 'TRK-${now.millisecondsSinceEpoch}',
        mode: ScanMode.tracker,
        platform: platform,
        startedAt: now,
        finishedAt: now,
        findings: findings,
        coverage: const [],
      ),
      retentionDays: settings.retentionDays,
    );
    notifyListeners();
    return ('ok', findings);
  }

  /// Obtains an anonymous device token from the configured backend (HTTPS only).
  Future<String> registerWithBackend(String url) async {
    final base = Uri.tryParse(url);
    if (base == null || (base.scheme != 'https' && base.host != '10.0.2.2')) return 'HTTPS required';
    try {
      final res = await http
          .post(base.resolve('/v1/devices/register'), headers: {'Content-Type': 'application/json'}, body: '{}')
          .timeout(const Duration(seconds: 10));
      if (res.statusCode != 201) return 'HTTP ${res.statusCode}';
      final token = (jsonDecode(res.body) as Map<String, dynamic>)['token'] as String;
      await updateSettings((s) {
        s.backendUrl = url;
        s.backendToken = token;
      });
      return 'ok';
    } catch (e) {
      return '$e';
    }
  }

  Future<String> updateRulePack() async {
    if (!settings.backendConfigured) return 'notConfigured';
    try {
      final p = await loader.update(Uri.parse(settings.backendUrl), settings.backendToken, currentVersion: pack.version);
      pack = p;
      settings.minRulePackVersion = p.version;
      await repo.saveSettings(settings);
      intel = _buildIntel();
      notifyListeners();
      return 'ok';
    } catch (e) {
      return '$e';
    }
  }

  Future<void> deleteHistory() async {
    await repo.deleteHistory();
    reports = [];
    incidents = {};
    trackers = [];
    notifyListeners();
  }

  Future<void> wipeAll() async {
    await repo.wipeAll();
    settings = AppSettings();
    reports = [];
    incidents = {};
    trackers = [];
    try {
      await BackgroundScheduler.disable();
    } catch (_) {}
    notifyListeners();
  }
}
