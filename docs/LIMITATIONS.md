# Known limitations (honest list)

## Platform limits (cannot be fixed by an app)
- **No app can prove a phone is clean.** Root-level or zero-click spyware (e.g. mercenary spyware) can hide from every API Sentinel uses. For high-risk users: forensic tools such as Amnesty Tech's MVT, or a helpline (Access Now Digital Security Helpline).
- **Call interception, SS7 abuse, IMSI catchers** are not detectable from a phone app; the app says "Unable to verify whether this call is being intercepted…".
- **Other apps' microphone use** is not visible to third-party apps on Android or iOS; Sentinel links to Privacy Dashboard / explains the indicator dot.
- **iOS**: no app inventory, no configuration-profile listing, no Wi-Fi security type, no user-CA list, Apple Find My adverts hidden from CoreBluetooth, `tel:` links cannot contain `*`/`#`, background refresh timing decided by iOS.
- **Android**: notification-listener list hidden on some versions; app-op modes of other apps may be unreadable (reported "unknown"); `getprop` boot state may be blocked by vendors; Wi-Fi security type only on Android 12+.
- Bluetooth tracker detection is partial: rotating identifiers, GPS trackers with SIM cards and trackers not advertising are invisible.

## Product limits (could be added)
- **Bundled indicators are test fixtures only.** Real IOC coverage requires running the backend, importing feeds and publishing a signed pack.
- **iOS Share Extension not implemented.** Creating a separate Xcode extension target requires Xcode and an App Group; the closest alternative is implemented: `sentinel://scan?url=…` (works from Shortcuts: "Open URL" action) and paste-to-check.
- **Play Integrity / App Attest** not wired (needs a Google Cloud project / Apple team and server verification). Root/jailbreak checks are heuristics.
- Mobile app does not yet expose the backend's incident-sync endpoint in the UI (the API is implemented and tested).
- Localisation: French and English only.
- Release APK is signed with the **debug key** unless `android/key.properties` (or CI secrets) are provided — fine for side-loading tests, not for Play.

## Not verified in the build environment
See `TESTING.md` — in particular: no physical device or emulator was available (no KVM), the iOS app was compiled only in CI (macOS runner), never run on an iPhone, Docker Compose could not be started (no Docker daemon), and battery consumption was not measured.
