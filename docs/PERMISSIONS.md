# Permission justification

## Android (`app/android/app/src/main/AndroidManifest.xml`)

| Permission | When | Why | If denied |
|---|---|---|---|
| `INTERNET`, `ACCESS_NETWORK_STATE` | install-time | network posture, opt-in TLS probe, optional backend | network checks report "unavailable" |
| `QUERY_ALL_PACKAGES` | install-time | core function: inventory apps to detect stalkerware/malware indicators. Google Play permits it for device-security apps (declaration form required). | inventory flagged "limited visibility" |
| `REQUEST_DELETE_PACKAGES` | install-time (normal) | open the **system** uninstall dialog for an app the user chooses | uninstall button hidden |
| `POST_NOTIFICATIONS` | runtime, only when the user enables alerts | security alerts | alerts off |
| `BLUETOOTH_SCAN` (`neverForLocation`) | runtime, only when the user starts a tracker scan | detect nearby trackers | tracker scan unavailable |
| `BLUETOOTH`, `BLUETOOTH_ADMIN`, `ACCESS_FINE_LOCATION` (all `maxSdkVersion=30`) | runtime on Android 8–11 only, when starting a tracker scan | the OS requires location for BLE scans on those versions | tracker scan unavailable |

**Not requested:** contacts, SMS, call log, phone state, microphone, camera, background location, accessibility service, device admin, VPN service, storage (APK import uses the Storage Access Framework).

Other hardening: `allowBackup=false`, data-extraction rules exclude all data, cleartext disabled, user CAs not trusted (`network_security_config.xml`), R8 minification in release.

## iOS (`app/ios/Runner/Info.plist`)

| Key | Why |
|---|---|
| `NSBluetoothAlwaysUsageDescription` | tracker scan, prompted only when started |
| `NSFaceIDUsageDescription` | `LAContext` policy check (the app never authenticates the user) |
| `LSApplicationQueriesSchemes` (cydia, sileo, zbra, filza) | jailbreak-indicator check via `canOpenURL` |
| `BGTaskSchedulerPermittedIdentifiers`, `UIBackgroundModes: fetch` | daily assessment through `BGAppRefreshTask` |
| `CFBundleURLTypes` `sentinel://` | receive links to check (`sentinel://scan?url=…`) |

No location, microphone, contacts or photo permission is requested on iOS.

### Permissions merged from plugins (verified with `aapt2 dump badging` on the release APK)

| Permission | Added by | Purpose |
|---|---|---|
| `RECEIVE_BOOT_COMPLETED`, `WAKE_LOCK`, `FOREGROUND_SERVICE` | `workmanager` (AndroidX WorkManager) | keep the daily assessment scheduled after reboot |
| `FOREGROUND_SERVICE_SHORT_SERVICE` | AndroidX WorkManager | expedited work support (not used by Sentinel) |
| `VIBRATE` | `flutter_local_notifications` | alert vibration |
| `io.sentinel.mobilesoc.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` | AndroidX core | protects non-exported dynamic receivers (signature-level) |

None of these grant access to user data.
