import 'models.dart';

/// Installed application as observed through PackageManager (Android only).
class AppInfo {
  AppInfo.fromMap(Map<String, dynamic> m)
    : package = m['package'] as String? ?? '',
      label = m['label'] as String? ?? (m['package'] as String? ?? ''),
      versionName = m['versionName'] as String?,
      firstInstall = _date(m['firstInstall']),
      lastUpdate = _date(m['lastUpdate']),
      isSystem = m['isSystem'] == true,
      debuggable = m['debuggable'] == true,
      enabled = m['enabled'] != false,
      targetSdk = (m['targetSdk'] as num?)?.toInt(),
      hasLauncher = m['hasLauncher'] != false,
      installer = (m['installer'] as Map?)?['installing'] as String?,
      initiatingInstaller = (m['installer'] as Map?)?['initiating'] as String?,
      requestedPermissions = _strings(m['requestedPermissions']),
      grantedPermissions = _strings(m['grantedPermissions']).toSet(),
      boundServicePermissions = _strings(m['boundServicePermissions']).toSet(),
      receiverPermissions = _strings(m['receiverPermissions']).toSet(),
      signingSha256 = _strings(m['signingSha256']),
      appOps = ((m['appOps'] as Map?) ?? const {}).map((k, v) => MapEntry('$k', '$v'));

  final String package;
  final String label;
  final String? versionName;
  final DateTime? firstInstall;
  final DateTime? lastUpdate;
  final bool isSystem;
  final bool debuggable;
  final bool enabled;
  final int? targetSdk;
  final bool hasLauncher;
  final String? installer;
  final String? initiatingInstaller;
  final List<String> requestedPermissions;
  final Set<String> grantedPermissions;
  final Set<String> boundServicePermissions;
  final Set<String> receiverPermissions;
  final List<String> signingSha256;
  final Map<String, String> appOps;

  static const trustedStores = {
    'com.android.vending', // Google Play
    'com.google.android.packageinstaller.store', // reserved
    'com.sec.android.app.samsungapps', // Galaxy Store
    'com.huawei.appmarket', // AppGallery
    'com.amazon.venezia', // Amazon Appstore
    'com.xiaomi.market', // Xiaomi GetApps
    'com.xiaomi.mipicks',
    'com.heytap.market', // OPPO
    'com.oppo.market',
    'com.bbk.appstore', // vivo
    'org.fdroid.fdroid', // F-Droid (reproducible, but not Play-reviewed)
  };

  /// Installed outside known app stores (package installer, browser, adb or unknown).
  bool get isSideloaded => !isSystem && (installer == null || !trustedStores.contains(installer));

  bool granted(String permission) => grantedPermissions.contains(permission);

  bool get isAccessibilityProvider => boundServicePermissions.contains('android.permission.BIND_ACCESSIBILITY_SERVICE');
  bool get isDeviceAdminProvider => receiverPermissions.contains('android.permission.BIND_DEVICE_ADMIN');
  bool get isNotificationListenerProvider => boundServicePermissions.contains('android.permission.BIND_NOTIFICATION_LISTENER_SERVICE');
  bool get isVpnProvider => boundServicePermissions.contains('android.permission.BIND_VPN_SERVICE');

  static DateTime? _date(Object? v) => v is num ? DateTime.fromMillisecondsSinceEpoch(v.toInt()) : null;
  static List<String> _strings(Object? v) => (v as List?)?.map((e) => '$e').toList() ?? const [];
}

/// Everything the engine knows about the device for one scan.
class DeviceSnapshot {
  DeviceSnapshot({
    required this.platform,
    required this.device,
    required this.network,
    required this.apps,
    required this.appInventorySupported,
    this.appInventoryLimited = false,
    DateTime? collectedAt,
  }) : collectedAt = collectedAt ?? DateTime.now();

  final DevicePlatform platform;
  final Map<String, dynamic> device;
  final Map<String, dynamic> network;
  final List<AppInfo> apps;
  final bool appInventorySupported;
  final bool appInventoryLimited;
  final DateTime collectedAt;

  T? d<T>(String key) {
    final v = device[key];
    return v is T ? v : null;
  }

  T? n<T>(String key) {
    final v = network[key];
    return v is T ? v : null;
  }

  List<Map<String, dynamic>> list(String key) => ((device[key] as List?) ?? const []).whereType<Map>().map((e) => Map<String, dynamic>.from(e)).toList();

  bool probeAvailable(String key) => !(((device['unavailableProbes'] as List?) ?? const []).contains(key));

  AppInfo? app(String? package) {
    if (package == null) return null;
    for (final a in apps) {
      if (a.package == package) return a;
    }
    return null;
  }

  String labelFor(String? package) => app(package)?.label ?? package ?? '?';
}
