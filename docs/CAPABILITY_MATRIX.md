# Platform capability matrix

Legend: ✅ implemented with a public API · 🟡 partial / best effort · ❌ not possible for a standard store app (closest legitimate alternative in brackets).

| Capability | Android (standard app) | iOS (App Store app) | Implementation |
|---|---|---|---|
| Installed-app inventory | ✅ `PackageManager` + `QUERY_ALL_PACKAGES` (Play allows it for security apps) | ❌ sandbox [App Privacy Report guidance] | `AppInventory.kt` |
| Granted permissions per app | ✅ `requestedPermissionsFlags` | ❌ | `AppInventory.kt` |
| Install source (store vs side-load) | ✅ `getInstallSourceInfo` (API 30+) | ❌ | `AppInventory.kt` |
| Signing certificate SHA-256 | ✅ `GET_SIGNING_CERTIFICATES` | ❌ | `AppInventory.kt` |
| Special access (overlay, usage stats, install apps) | 🟡 app-ops readable on most builds, else "unknown" | ❌ | `AppInventory.appOpsFor` |
| Enabled accessibility services | ✅ `AccessibilityManager` | ❌ | `DeviceInspector.kt` |
| Active device admins / device & profile owner | ✅ `DevicePolicyManager` | ❌ [Settings → VPN & Device Management guidance] | `DeviceInspector.kt` |
| Notification listeners | 🟡 `Settings.Secure` (hidden on some versions → reported unavailable) | ❌ | `DeviceInspector.kt` |
| Default keyboard | ✅ | ❌ | `DeviceInspector.kt` |
| Screen lock / passcode | ✅ `KeyguardManager.isDeviceSecure` | ✅ `LAContext` | both |
| Storage encryption | ✅ `DevicePolicyManager` | ✅ implied by passcode (Data Protection) | |
| OS version & security patch | ✅ `Build.VERSION.SECURITY_PATCH` | 🟡 version only (compared with rule-pack `iosLatestMajor`) | |
| USB debugging / developer options | ✅ `Settings.Global` | ❌ | |
| Root / jailbreak indicators | 🟡 su paths, root managers, test-keys, `getprop` boot state | 🟡 files, URL schemes, injected dylibs, sandbox write | never conclusive |
| Play Integrity / App Attest | 🟡 not configured by default (needs server + Play Console) | 🟡 not configured | documented in LIMITATIONS |
| User-installed CA certificates | ✅ `AndroidCAStore` `user:` aliases | ❌ | |
| VPN active | ✅ `NetworkCapabilities.TRANSPORT_VPN` | ✅ scoped proxy interfaces (utun/ipsec/ppp) | |
| HTTP proxy / PAC | ✅ `LinkProperties.httpProxy` | ✅ `CFNetworkCopySystemProxySettings` | |
| Wi-Fi security type | 🟡 Android 12+ `WifiInfo.currentSecurityType` | ❌ (needs hotspot entitlement) | |
| Private DNS | ✅ Android 9+ | ❌ | |
| TLS interception probe | ✅ opt-in, system trust store | ✅ opt-in | `network_probe.dart` |
| Phishing URL heuristics + IDN/homograph | ✅ offline | ✅ offline | `url_analyzer.dart` |
| Redirect-chain analysis (headers only) | ✅ opt-in per check | ✅ | |
| Share a link into the app | ✅ `ACTION_SEND` intent filter | 🟡 `sentinel://scan?url=` URL scheme (Share Extension not built — see LIMITATIONS) | |
| Clipboard analysis | ✅ only on explicit paste tap | ✅ only on explicit paste tap | |
| APK static analysis | ✅ SAF picker → hash, manifest, signature, YARA-lite | ❌ (no APKs on iOS) | `ApkInspector.kt`, `apk_analyzer.dart` |
| Bluetooth tracker scan | 🟡 Find My (separated), SmartTag, Tile, FMDN | 🟡 SmartTag, Tile, FMDN only (iOS hides Find My adverts) | `BleTrackerScanner.kt`, Swift `TrackerScanner` |
| Apps holding microphone permission | ✅ | ❌ [Settings → Privacy → Microphone] | |
| Other apps' live/past microphone use | ❌ [Privacy Dashboard deep link] | ❌ [orange dot, App Privacy Report] | |
| Call forwarding status | 🟡 dialer pre-filled with `*#21#` (user presses call) | ❌ iOS blocks `*`/`#` in `tel:` [manual instructions] | |
| Call interception / SS7 / IMSI catcher | ❌ — app displays "Unable to verify…" | ❌ same | by design |
| Background daily assessment | ✅ WorkManager (battery-aware, may be deferred) | 🟡 `BGAppRefreshTask`, iOS decides if/when | `background.dart` |
| Local notifications | ✅ (POST_NOTIFICATIONS asked when enabled) | ✅ | |
| Encrypted local storage | ✅ AES-256-GCM, key in Keystore-backed storage | ✅ key in Keychain (this-device-only) | `secure_store.dart` |
