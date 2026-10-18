import 'dart:io';

import 'package:flutter/widgets.dart';
import 'package:sentinel_native/sentinel_native.dart';
import 'package:workmanager/workmanager.dart';

import '../core/models.dart';
import 'notifier.dart';
import 'platform_source.dart';
import 'repository.dart';
import 'rule_pack_loader.dart';
import 'scan_coordinator.dart';
import 'secure_store.dart';

const dailyTaskName = 'io.sentinel.dailyAssessment';
const dailyUniqueName = 'sentinel-daily';

/// Entry point for OS-scheduled runs (Android WorkManager / iOS BGAppRefreshTask).
/// The OS decides when, and whether, this runs; the UI always shows the actual
/// last completed scan time instead of assuming it happened.
@pragma('vm:entry-point')
void callbackDispatcher() {
  Workmanager().executeTask((task, input) async {
    WidgetsFlutterBinding.ensureInitialized();
    try {
      final repo = Repository(SecureStore(keys: PlatformKeyProvider()));
      final settings = await repo.loadSettings();
      if (!settings.dailyAssessment) return true;
      final pack = await RulePackLoader(repo).load(minimumVersion: settings.minRulePackVersion);
      await ScanCoordinator(
        repo: repo,
        source: PlatformSnapshotSource(SentinelNative()),
        notifier: Notifier(),
      ).run(mode: ScanMode.daily, pack: pack, settings: settings, background: true);
      return true;
    } catch (_) {
      // Returning false lets WorkManager retry with backoff; the overdue banner covers persistent failure.
      return false;
    }
  });
}

class BackgroundScheduler {
  static bool get supported => Platform.isAndroid || Platform.isIOS;

  static Future<void> init() async {
    if (!supported) return;
    await Workmanager().initialize(callbackDispatcher);
  }

  static Future<void> enable() async {
    if (!supported) return;
    await Workmanager().registerPeriodicTask(
      Platform.isIOS ? dailyTaskName : dailyUniqueName,
      dailyTaskName,
      frequency: const Duration(hours: 24),
      constraints: Constraints(networkType: NetworkType.notRequired, requiresBatteryNotLow: true),
      existingWorkPolicy: ExistingPeriodicWorkPolicy.update,
    );
  }

  static Future<void> disable() async {
    if (!supported) return;
    await Workmanager().cancelByUniqueName(Platform.isIOS ? dailyTaskName : dailyUniqueName);
  }
}
