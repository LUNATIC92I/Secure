// Benign, synthetic device fixtures. No real malware is involved anywhere in the test suite.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:sentinel_mobile_soc/core/models.dart';
import 'package:sentinel_mobile_soc/core/snapshot.dart';
import 'package:sentinel_mobile_soc/detection/rule_pack.dart';
import 'package:sentinel_mobile_soc/engine/scan_engine.dart';

const p = 'android.permission.';

Map<String, dynamic> app(
  String pkg, {
  String? label,
  bool system = false,
  bool launcher = true,
  String? installer = 'com.android.vending',
  List<String> granted = const [],
  List<String> services = const [],
  List<String> receivers = const [],
  List<String>? certs,
  Map<String, String> ops = const {},
  bool debuggable = false,
}) =>
    {
      'package': pkg,
      'label': label ?? pkg.split('.').last,
      'isSystem': system,
      'hasLauncher': launcher,
      'installer': {'installing': installer},
      'requestedPermissions': granted,
      'grantedPermissions': granted,
      'boundServicePermissions': services,
      'receiverPermissions': receivers,
      'signingSha256': certs ?? ['a' * 64],
      'appOps': ops,
      'debuggable': debuggable,
      'firstInstall': 1700000000000,
    };

Map<String, dynamic> cleanAndroidDevice({String patch = '2026-09-05'}) => {
      'platform': 'android',
      'osVersion': '16',
      'sdkInt': 36,
      'securityPatch': patch,
      'deviceSecure': true,
      'encryptionStatus': 'active',
      'adbEnabled': false,
      'developerOptions': false,
      'buildTags': 'release-keys',
      'isEmulator': false,
      'accessibilityServices': <Map<String, dynamic>>[],
      'deviceAdmins': <Map<String, dynamic>>[],
      'notificationListeners': <String>[],
      'inputMethods': [
        {'id': 'com.google.android.inputmethod.latin/.LatinIME', 'package': 'com.google.android.inputmethod.latin', 'isSystem': true}
      ],
      'defaultInputMethod': 'com.google.android.inputmethod.latin/.LatinIME',
      'userCaCertificates': <Map<String, dynamic>>[],
      'root': {'suPaths': <String>[], 'rootManagers': <String>[], 'testKeys': false},
      'bootProps': {'ro.boot.verifiedbootstate': 'green', 'ro.boot.flash.locked': '1'},
      'unavailableProbes': <String>[],
    };

Map<String, dynamic> wifiNetwork({String security = 'wpa3-sae', bool vpn = false, Map<String, dynamic>? proxy}) => {
      'connected': true,
      'transport': 'wifi',
      'vpnActive': vpn,
      'validated': true,
      'captivePortal': false,
      'proxy': proxy,
      'privateDnsActive': true,
      'wifiSecurity': security,
    };

/// Ordinary phone: messaging app with mic/contacts, maps with background location.
List<Map<String, dynamic>> benignApps() => [
      app('com.android.settings', system: true, installer: null, granted: ['${p}RECORD_AUDIO']),
      app('org.thoughtcrime.securesms', label: 'Signal', granted: ['${p}RECORD_AUDIO', '${p}CAMERA', '${p}READ_CONTACTS', '${p}READ_SMS']),
      app('com.google.android.apps.maps', label: 'Maps', granted: ['${p}ACCESS_FINE_LOCATION', '${p}ACCESS_BACKGROUND_LOCATION']),
      app('com.example.notes', label: 'Notes'),
    ];

/// Synthetic stalkerware-like profile built from benign metadata only.
Map<String, dynamic> stalkerApp() => app(
      'com.system.update.service',
      label: 'System Service',
      launcher: false,
      installer: 'com.google.android.packageinstaller',
      granted: ['${p}RECORD_AUDIO', '${p}ACCESS_FINE_LOCATION', '${p}ACCESS_BACKGROUND_LOCATION', '${p}READ_SMS', '${p}READ_CALL_LOG'],
      services: ['${p}BIND_ACCESSIBILITY_SERVICE', '${p}BIND_NOTIFICATION_LISTENER_SERVICE'],
      receivers: ['${p}BIND_DEVICE_ADMIN'],
      ops: {'usageStats': 'allowed'},
    );

DeviceSnapshot androidSnapshot({
  Map<String, dynamic>? device,
  Map<String, dynamic>? network,
  List<Map<String, dynamic>>? apps,
}) =>
    DeviceSnapshot(
      platform: DevicePlatform.android,
      device: device ?? cleanAndroidDevice(),
      network: network ?? wifiNetwork(),
      apps: (apps ?? benignApps()).map(AppInfo.fromMap).toList(),
      appInventorySupported: true,
    );

DeviceSnapshot iosSnapshot({bool passcode = true, Map<String, dynamic>? jailbreak, String version = '26.0.1'}) => DeviceSnapshot(
      platform: DevicePlatform.ios,
      device: {
        'platform': 'ios',
        'osVersion': version,
        'deviceSecure': passcode,
        'isSimulator': false,
        'debuggerAttached': false,
        'jailbreak': jailbreak ?? {'paths': [], 'schemes': [], 'dylibs': [], 'sandboxWritable': false},
        'vpnActive': false,
      },
      network: {'connected': true, 'transport': 'wifi', 'vpnActive': false, 'wifiSecurity': null},
      apps: const [],
      appInventorySupported: false,
    );

class FixtureSource implements SnapshotSource {
  FixtureSource(this.snap, {this.fail = false});
  final DeviceSnapshot snap;
  final bool fail;
  @override
  Future<DeviceSnapshot> collect({required bool includeApps}) async {
    if (fail) throw StateError('platform channel unavailable');
    return snap;
  }
}

/// The bundled, signed rule pack loaded straight from disk.
Future<RulePack> bundledPack() async {
  final body = await File('assets/rules/rulepack.json').readAsBytes();
  final sig = await File('assets/rules/rulepack.json.sig').readAsString();
  return RulePack.loadVerified(Uint8List.fromList(body), sig);
}

RulePack packWith(List<Map<String, dynamic>> indicators, {Map<String, dynamic> config = const {}}) => RulePack.parse(jsonEncode({
      'schema': 1,
      'version': 7,
      'indicators': indicators,
      'config': config,
      'yara': '',
    }));
