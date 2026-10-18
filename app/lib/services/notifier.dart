import 'package:flutter_local_notifications/flutter_local_notifications.dart';

import '../core/models.dart';

/// Decides which findings deserve a notification. Pure, unit-tested.
class NotificationPolicy {
  /// Returns findings to notify and updates [notified] (fingerprint → severity).
  static List<Finding> select(List<Finding> findings, Map<String, String> notified, {required bool highOnly}) {
    final out = <Finding>[];
    final threshold = highOnly ? Severity.high : Severity.medium;
    for (final f in findings) {
      if (!f.isActive || f.classification == Classification.informational) continue;
      if (f.severity.index < threshold.index) continue;
      final prev = notified[f.id];
      // Re-notify only if the severity increased since the last alert.
      if (prev != null && Severity.values.byName(prev).index >= f.severity.index) continue;
      notified[f.id] = f.severity.name;
      out.add(f);
    }
    return out;
  }
}

class Notifier {
  Notifier();

  final _plugin = FlutterLocalNotificationsPlugin();
  bool _ready = false;

  static const _channel = AndroidNotificationDetails(
    'security_alerts',
    'Security alerts',
    channelDescription: 'New high-impact security findings',
    importance: Importance.high,
    priority: Priority.high,
    groupKey: 'io.sentinel.alerts',
  );

  Future<void> init() async {
    if (_ready) return;
    await _plugin.initialize(
      settings: const InitializationSettings(
        android: AndroidInitializationSettings('@mipmap/ic_launcher'),
        iOS: DarwinInitializationSettings(requestAlertPermission: false, requestBadgePermission: false, requestSoundPermission: false),
      ),
    );
    _ready = true;
  }

  Future<bool> requestPermission() async {
    await init();
    final android = _plugin.resolvePlatformSpecificImplementation<AndroidFlutterLocalNotificationsPlugin>();
    if (android != null) return await android.requestNotificationsPermission() ?? false;
    final ios = _plugin.resolvePlatformSpecificImplementation<IOSFlutterLocalNotificationsPlugin>();
    if (ios != null) return await ios.requestPermissions(alert: true, badge: false, sound: true) ?? false;
    return false;
  }

  /// One notification per batch, grouped, so a scan never floods the shade.
  Future<void> notifyFindings(List<Finding> findings, String lang) async {
    if (findings.isEmpty) return;
    await init();
    final top = findings.first;
    final certainty = switch (top.confidence) {
      Confidence.high => lang == 'fr' ? 'confiance élevée' : 'high confidence',
      Confidence.medium => lang == 'fr' ? 'confiance moyenne' : 'medium confidence',
      Confidence.low => lang == 'fr' ? 'confiance faible' : 'low confidence',
    };
    final title = findings.length == 1
        ? top.title.of(lang)
        : (lang == 'fr' ? '${findings.length} nouveaux problèmes de sécurité' : '${findings.length} new security issues');
    final next = top.remediation.isEmpty ? '' : ' → ${top.remediation.first.label.of(lang)}';
    await _plugin.show(
      id: 1001,
      title: title,
      body: '${top.severity.name.toUpperCase()} · $certainty$next',
      notificationDetails: const NotificationDetails(android: _channel, iOS: DarwinNotificationDetails(threadIdentifier: 'alerts')),
    );
  }

  Future<void> notifyText(int id, String title, String body) async {
    await init();
    await _plugin.show(id: id, title: title, body: body, notificationDetails: const NotificationDetails(android: _channel));
  }
}
