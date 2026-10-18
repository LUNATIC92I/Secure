# Architecture

```
┌──────────────────────── Flutter app (Dart) ────────────────────────┐
│ UI (lib/ui)  ── 23 screens, FR/EN, dark SOC theme, a11y semantics  │
│      │                                                             │
│ AppState (lib/state) ── ChangeNotifier, single source of truth     │
│      │                                                             │
│ ScanCoordinator ── ScanEngine ── DetectionRule[] (lib/detection)   │
│      │                │            ├─ android_rules.dart (21)      │
│      │                │            ├─ common_rules.dart (9)        │
│      │                │            └─ RulePack (signed IOCs+YARA)  │
│      │                ├─ NetworkProbe (opt-in TLS)                  │
│      │                └─ SecurityScore                              │
│      ├─ IncidentManager · NotificationPolicy · TrackerAssessor      │
│      ├─ UrlAnalyzer · ApkAnalyzer (isolate) · IntelService          │
│      └─ Repository → SecureStore (AES-256-GCM, Keystore/Keychain)  │
│                                                                     │
│ SnapshotSource ── PlatformSnapshotSource ── sentinel_native (plugin)│
└──────────────────────────────┬──────────────────────────────────────┘
               MethodChannel "io.sentinel/native"
        ┌──────────────────────┴───────────────────────┐
   Android (Kotlin)                               iOS (Swift)
   DeviceInspector  AppInventory                  SentinelNativePlugin
   NetworkInspector ApkInspector                  (LAContext, jailbreak
   BleTrackerScanner, settings/uninstall intents   probes, NWPathMonitor,
                                                   CFNetwork proxy, CoreBluetooth)

Optional backend (backend/, FastAPI + PostgreSQL)
  /v1/devices/register · /v1/reputation · /v1/rules/latest (Ed25519-signed)
  /v1/incidents (opt-in sync, device-scoped) · /v1/me (erasure) · /v1/admin/* (RBAC, audit)
```

## Design principles

1. **Native code observes, Dart decides.** Kotlin/Swift return raw observations (maps); all classification, scoring and wording live in one shared, unit-tested Dart engine. A probe that fails is listed in `unavailableProbes`, and the corresponding rule reports *unavailable* coverage instead of passing silently.
2. **Rules are self-describing** (`DetectionRule`: id, version, platforms, required capabilities, confidence model, known false positives, remediation). Data-driven indicators and YARA-lite rules ship in a signed rule pack that can be updated without an app release. See `DETECTION_RULES.md`.
3. **Classification is explicit**: confirmed malicious (exact IOC match on hash/cert), suspicious (behaviour correlation), exposure (configuration), to verify, informational.
4. **Local-first**: the app is fully functional offline; the backend is optional and used only after explicit consent.
5. **Never act silently**: remediation opens system screens (settings, uninstall dialog, dialer) — the OS asks the user for the final confirmation; destructive in-app actions (erase data, close incident) have confirmation dialogs.

## Plugin in background isolates

The native bridge is a Flutter plugin (`app/packages/sentinel_native`) rather than code in `MainActivity`, so the WorkManager / BGTaskScheduler headless engine gets it registered too and the daily assessment can run the same engine.

## Data flow of a scan

1. `PlatformSnapshotSource.collect` → device, network and app maps.
2. `ScanEngine.run` evaluates every applicable rule, records coverage, optionally runs the TLS probe, appends manual-check coverage items.
3. `ScanCoordinator` re-applies stored false-positive feedback, stores the report (retention window), updates incidents, and asks `NotificationPolicy` which findings deserve one grouped notification.
