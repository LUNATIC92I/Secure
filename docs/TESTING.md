# Test report & matrix

Environment: Linux x86_64 container, Flutter 3.47.7 / Dart 3.13.5, Android SDK 36 / build-tools 36.0.0, JDK 21, Python 3.13. **No Android emulator (no KVM), no physical device, no macOS/Xcode, no Docker daemon.**

## Automated results (this environment, 2026-10-18)

| Suite | Command | Result |
|---|---|---|
| Dart static analysis (app + plugin) | `flutter analyze` | ✅ 0 issues |
| Dart unit + widget tests | `flutter test` | ✅ 73 passed, 1 skipped (E2E, needs a server) |
| App ↔ backend E2E contract | `SENTINEL_E2E_URL=… flutter test test/e2e_backend_test.dart` against local uvicorn + SQLite | ✅ passed (register → import IOC → publish signed pack → app verifies with pinned key → hashed-domain reputation = malicious) |
| Backend API tests | `pytest -q` | ✅ 14 passed |
| Backend lint (incl. bandit-style `S` rules) | `ruff check .` | ✅ clean |
| Alembic migration | `alembic upgrade head` (SQLite) | ✅ (bug found and fixed: CLI could not import `app`) |
| Android debug + release build | `flutter build apk --release [--split-per-abi]` | ✅ builds; manifest/permissions verified with `aapt2 dump badging`; signature checked with `apksigner` (debug key) |
| Kotlin native module compile | part of the Gradle build | ✅ |
| iOS build | `flutter build ios --no-codesign` | ⏳ not runnable here — configured in GitHub Actions (`.github/workflows/mobile.yml`, macOS runner) |
| Swift native module compile | — | ⏳ unverified until the macOS CI job runs |
| Docker Compose stack | `docker compose up` | ⏳ not verified (no Docker daemon) |

## Test categories

| Category | Where | Status |
|---|---|---|
| Unit (rules, scoring, engine, YARA, URL, incidents, notifications, trackers, storage, intel, APK) | `app/test/*.dart` | ✅ |
| Widget / UI | `app/test/widget_test.dart` (onboarding, FR dashboard, results, tablet layout, reduced motion) | ✅ |
| Accessibility | semantic label on score ring, live region on scan progress, reduced-motion path | ✅ partial — no TalkBack/VoiceOver session on device |
| Permission handling | denied/unavailable probes → "unavailable" coverage (`detection_rules_test`), permission-denied tracker path in UI | ✅ logic · ⏳ on-device prompts |
| Offline mode | `widget_test` offline case, intel provider consent tests | ✅ |
| Background scheduling | WorkManager/BGTask registration code compiled (Android) | ⏳ on-device execution not observed |
| Threat classification | confirmed vs suspicious vs exposure tests | ✅ |
| False-positive tests | benign phone (Signal, Maps) yields no medium+ finding; FP feedback persists | ✅ |
| Security regression | rule-pack tamper/untrusted key/rollback, AES-GCM tamper + AAD swap, IDOR on incidents, RBAC, rate limit, body limit, validation without echo | ✅ |
| API tests | `backend/tests/test_api.py` | ✅ |
| Dependency audit | CI: `flutter pub outdated`, `pip-audit` | ⏳ runs in CI |
| Performance | APK YARA scan runs in an isolate, 64 MB per-entry cap | ⏳ not benchmarked on device |
| Battery | — | ⏳ not measured (requires device + Battery Historian) |

## Manual test checklist for your device (please report results)

1. Install `app-arm64-v8a-release.apk` (most phones) → allow "install unknown apps" for your file manager.
2. Onboarding → capability matrix shows Android column.
3. Quick scan → results show coverage list; Comprehensive scan → per-app rules.
4. Modules → Application risk: list appears (if only a few apps: package visibility issue, please report).
5. Enable USB debugging → rescan → "USB debugging is enabled" appears; disable → mark resolved.
6. Phishing: check `https://testsafebrowsing.appspot.com/s/phishing.html` → "Known malicious [TEST]".
7. Share a link from Chrome → "Sentinel SOC" → scanner opens with the link.
8. APK analysis: pick any APK (e.g. from APKMirror) → hash, permissions, signature shown.
9. Tracker scan → Bluetooth permission prompt appears only now.
10. Call & mic → "*#21#" opens the dialer pre-filled (nothing is dialled automatically).
11. Settings → Notifications → enable → system permission prompt → "Send test notification".
12. Daily assessment ON → next day check dashboard "last scan … Run by the OS scheduler".
