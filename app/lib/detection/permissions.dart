import '../core/models.dart';

/// Sensitive Android permissions and why they matter. Requesting any of these is
/// normal for many legitimate apps; they only become meaningful in combination.
class SensitivePermission {
  const SensitivePermission(this.name, this.group, this.weight, this.why);

  final String name;
  final String group;

  /// Contribution to the spyware-capability score (0-3).
  final int weight;
  final LText why;
}

const _p = 'android.permission.';

const sensitivePermissions = <SensitivePermission>[
  SensitivePermission('${_p}RECORD_AUDIO', 'microphone', 3, LText('Can record audio from the microphone', 'Peut enregistrer l’audio du micro')),
  SensitivePermission('${_p}CAMERA', 'camera', 2, LText('Can take photos and video', 'Peut prendre des photos et vidéos')),
  SensitivePermission('${_p}ACCESS_FINE_LOCATION', 'location', 2, LText('Precise location', 'Localisation précise')),
  SensitivePermission('${_p}ACCESS_BACKGROUND_LOCATION', 'location', 3, LText('Location while the app is closed', 'Localisation même app fermée')),
  SensitivePermission('${_p}READ_SMS', 'sms', 3, LText('Read text messages (incl. one-time codes)', 'Lire les SMS (y compris codes à usage unique)')),
  SensitivePermission('${_p}RECEIVE_SMS', 'sms', 2, LText('Intercept incoming SMS', 'Intercepter les SMS entrants')),
  SensitivePermission('${_p}SEND_SMS', 'sms', 2, LText('Send SMS (possible premium fraud)', 'Envoyer des SMS (fraude possible)')),
  SensitivePermission('${_p}READ_CALL_LOG', 'calls', 3, LText('Read call history', 'Lire l’historique des appels')),
  SensitivePermission('${_p}PROCESS_OUTGOING_CALLS', 'calls', 2, LText('See outgoing call numbers', 'Voir les numéros appelés')),
  SensitivePermission('${_p}READ_PHONE_STATE', 'calls', 1, LText('Phone state and identifiers', 'État du téléphone et identifiants')),
  SensitivePermission('${_p}ANSWER_PHONE_CALLS', 'calls', 2, LText('Answer calls programmatically', 'Répondre aux appels automatiquement')),
  SensitivePermission('${_p}CALL_PHONE', 'calls', 1, LText('Place calls without the dialer', 'Passer des appels sans le composeur')),
  SensitivePermission('${_p}READ_CONTACTS', 'contacts', 2, LText('Read contacts', 'Lire les contacts')),
  SensitivePermission('${_p}GET_ACCOUNTS', 'contacts', 1, LText('List device accounts', 'Lister les comptes')),
  SensitivePermission('${_p}READ_EXTERNAL_STORAGE', 'storage', 1, LText('Read shared storage', 'Lire le stockage partagé')),
  SensitivePermission('${_p}READ_MEDIA_IMAGES', 'storage', 1, LText('Read photos', 'Lire les photos')),
  SensitivePermission('${_p}BODY_SENSORS', 'sensors', 1, LText('Body sensors', 'Capteurs corporels')),
  SensitivePermission('${_p}ACTIVITY_RECOGNITION', 'sensors', 1, LText('Physical activity', 'Activité physique')),
];

final sensitiveByName = {for (final p in sensitivePermissions) p.name: p};

const permRecordAudio = '${_p}RECORD_AUDIO';
const permBackgroundLocation = '${_p}ACCESS_BACKGROUND_LOCATION';
const permFineLocation = '${_p}ACCESS_FINE_LOCATION';
const permCoarseLocation = '${_p}ACCESS_COARSE_LOCATION';
const permBluetoothScan = '${_p}BLUETOOTH_SCAN';
const permNearbyWifi = '${_p}NEARBY_WIFI_DEVICES';
const permRequestInstall = '${_p}REQUEST_INSTALL_PACKAGES';
const permSystemAlert = '${_p}SYSTEM_ALERT_WINDOW';
const permBindAccessibility = '${_p}BIND_ACCESSIBILITY_SERVICE';
const permBindDeviceAdmin = '${_p}BIND_DEVICE_ADMIN';
const permBindNotificationListener = '${_p}BIND_NOTIFICATION_LISTENER_SERVICE';
const permReceiveBoot = '${_p}RECEIVE_BOOT_COMPLETED';
const permForegroundMic = '${_p}FOREGROUND_SERVICE_MICROPHONE';
