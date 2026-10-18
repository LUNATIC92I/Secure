import 'dart:io';

import 'package:sentinel_native/sentinel_native.dart';

import '../core/models.dart';
import '../core/snapshot.dart';
import '../engine/scan_engine.dart';

/// Collects a [DeviceSnapshot] from the native plugin.
class PlatformSnapshotSource implements SnapshotSource {
  PlatformSnapshotSource(this.native);

  final SentinelNative native;

  @override
  Future<DeviceSnapshot> collect({required bool includeApps}) async {
    final platform = Platform.isAndroid ? DevicePlatform.android : (Platform.isIOS ? DevicePlatform.ios : DevicePlatform.unknown);
    final device = await native.deviceSnapshot();
    Map<String, dynamic> network;
    try {
      network = await native.networkSnapshot();
    } catch (_) {
      network = {};
    }
    var apps = <AppInfo>[];
    var supported = false;
    var limited = false;
    if (includeApps && platform == DevicePlatform.android) {
      final inv = await native.installedApps();
      apps = ((inv['apps'] as List?) ?? const []).map((e) => AppInfo.fromMap(Map<String, dynamic>.from(e as Map))).toList();
      supported = true;
      limited = inv['limitedVisibility'] == true;
    }
    return DeviceSnapshot(
      platform: platform,
      device: device,
      network: network,
      apps: apps,
      appInventorySupported: supported,
      appInventoryLimited: limited,
    );
  }
}
