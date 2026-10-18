# Build, install & release

## Prerequisites
Flutter 3.47.x (stable), JDK 17+ (21 used), Android SDK 36; for iOS: macOS with Xcode 26+ and CocoaPods/SwiftPM (Flutter handles it).

```bash
cd app
flutter pub get
flutter analyze && flutter test
```

## Android

```bash
flutter build apk --release --split-per-abi   # app-arm64-v8a-release.apk (~20 MB) for modern phones
flutter build apk --release                   # universal APK (~57 MB)
flutter build appbundle --release             # for Google Play
```

Install for testing: copy the APK to the phone and open it (allow "Install unknown apps"), or `adb install -r build/app/outputs/flutter-apk/app-arm64-v8a-release.apk`.

**Signing.** Without `android/key.properties` the release build is signed with the local debug key (fine for testing; different machines produce different keys, so uninstall before installing a build from another machine/CI). For a real release:

```bash
keytool -genkey -v -keystore android/app/release.jks -keyalg RSA -keysize 4096 -validity 10000 -alias sentinel
cat > android/key.properties <<EOP
storeFile=release.jks
storePassword=…
keyAlias=sentinel
keyPassword=…
EOP
```
Both files are git-ignored. In CI, set secrets `ANDROID_KEYSTORE_BASE64` and `ANDROID_KEY_PROPERTIES`.

**Google Play:** `QUERY_ALL_PACKAGES` requires the Permissions Declaration (category: device security / antivirus). Fill the Data safety form from `PRIVACY.md`.

## iOS

```bash
flutter build ios --release            # needs a signing team in Xcode (Runner → Signing & Capabilities)
flutter build ipa --release            # App Store / TestFlight
```
Unsigned build for side-loading tests (what CI produces):
```bash
flutter build ios --release --no-codesign
mkdir Payload && cp -R build/ios/iphoneos/Runner.app Payload/ && zip -qry sentinel-unsigned.ipa Payload
```
Install `sentinel-unsigned.ipa` on your iPhone with **Sideloadly** or **AltStore** (they re-sign it with your free Apple ID; 7-day validity) — or open `ios/Runner.xcworkspace` in Xcode, choose your team, plug in the iPhone and press Run. Enable *Settings → Privacy & Security → Developer Mode* when iOS asks.

Capabilities to keep in Xcode: Background Modes → Background fetch (already in Info.plist). BGTask identifier `io.sentinel.dailyAssessment`.

## CI (GitHub Actions)
`.github/workflows/mobile.yml` runs analyze + tests, then builds the Android release APK (artifact `sentinel-android-apk`) and an unsigned iOS IPA on a macOS runner (artifact `sentinel-ios-unsigned-ipa`). Download them from the run's *Artifacts* section.

## Backend

```bash
cd backend
cp .env.example .env        # fill POSTGRES_PASSWORD, SENTINEL_RULES_SIGNING_SEED, SENTINEL_ADMIN_BOOTSTRAP_TOKEN
docker compose up --build   # API on http://127.0.0.1:8000, OpenAPI at /docs
# first admin:
curl -X POST localhost:8000/v1/devices/register -H 'content-type: application/json' -d '{"bootstrap_token":"<token>"}'
# import feeds, publish a signed pack:
docker compose exec api python -m app.feeds urlhaus /data/csv_online.txt
curl -X POST localhost:8000/v1/admin/rules/publish -H "Authorization: Bearer <admin token>" -H 'content-type: application/json' -d '{"yara":"","config":{"iosLatestMajor":26}}'
```
Without Docker: `pip install -r requirements.txt && alembic upgrade head && uvicorn app.main:app`.

Production: run behind a TLS reverse proxy (the app refuses non-HTTPS backends except the emulator host 10.0.2.2), clear `SENTINEL_ADMIN_BOOTSTRAP_TOKEN` after the first admin, back up PostgreSQL, keep the signing seed in a secret manager.

In the app: *Settings → Threat intelligence → Backend URL → Register → Update rules*, then optionally enable *Cloud reputation*.
