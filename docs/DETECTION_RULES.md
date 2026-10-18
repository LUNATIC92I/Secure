# Detection rules

Two kinds of rules exist:

1. **Code rules** (`app/lib/detection/*_rules.dart`) — logic over device observations. Each declares: `id`, `version`, `name`, `description`, `platforms`, `requires` (capabilities), `available()` (does the OS expose what it needs), `confidenceModel`, `knownFalsePositives`, and returns findings with severity, confidence, classification, evidence, method, limitations and remediation.
2. **Data rules** in the signed **rule pack** (`app/assets/rules/rulepack.json` + `.sig`): indicators of compromise and YARA-lite rules, updatable from the backend without an app release.

## Rule pack format (schema 1)

```json
{
  "schema": 1, "version": 3, "issuedAt": "…", "source": "…",
  "config": {"androidPatchWarnDays": 90, "androidPatchCriticalDays": 365, "androidMinSupportedSdk": 31, "iosLatestMajor": 26},
  "indicators": [{"type": "package|cert_sha256|file_sha256|domain|url_prefix", "value": "…", "family": "…",
                  "category": "malware|stalkerware|phishing|adware|pua|test", "source": "…", "license": "…", "test": false}],
  "yara": "rule … { … }"
}
```

Validation before use: Ed25519 signature against `trustedRuleSigningKeys` → JSON schema → indicator type/value checks (hashes must be 64 lowercase hex) → YARA-lite parse (undefined identifiers, bad hex, duplicates rejected) → rollback check (`version ≥` last accepted). Any failure keeps the previous pack and surfaces the error.

**The bundled pack contains only test fixtures** (EICAR, Google Safe Browsing test URLs, `.invalid` domains, `io.sentinel.testfixture.*` packages). Real coverage comes from the backend importing feeds (`backend/app/feeds.py`: URLhaus CC0, Echap stalkerware-indicators) and publishing a signed pack.

## YARA-lite subset
Supported: `meta`, text strings with `nocase`/`wide`/`ascii`, hex strings with `??`, conditions with `and`/`or`/`not`/parentheses, `any|all|N of them`, `any|all|N of ($a, $b)`. Not supported (by design, to keep evaluation bounded): regex strings, modules, offsets/`at`/`in`, `filesize`. Meta keys used by the app: `severity`, `type` (`signature` ⇒ confirmed classification; anything else ⇒ heuristic), `title_en/fr`, `description(_fr)`.

## Code rule catalogue

| ID | Platform | Detects | Max severity / classification |
|---|---|---|---|
| AND-CFG-001 | Android | no secure lock screen | high / exposure |
| AND-CFG-002 | Android | storage not encrypted / default key | high / exposure |
| AND-CFG-003 | Android | USB debugging on | medium / exposure |
| AND-CFG-004 | Android | developer options on | low / exposure |
| AND-CFG-005 | Android | security patch older than pack thresholds | high / exposure |
| AND-CFG-006 | Android | SDK below pack minimum | medium / exposure |
| AND-INT-001 | Android | su binaries, root managers, test-keys | high / exposure |
| AND-INT-002 | Android | unlocked bootloader / non-green verified boot | high / exposure |
| AND-INT-003 | Android | emulator | info |
| AND-ACC-001 | Android | third-party accessibility service enabled | high / suspicious if side-loaded or hidden |
| AND-ADM-001 | Android | device admin / device-or-profile owner | high / suspicious if side-loaded |
| AND-NLS-001 | Android | notification-listener access | high / suspicious if side-loaded |
| AND-IME-001 | Android | third-party default keyboard | high if side-loaded |
| AND-NET-001 | Android | user-installed CA certificate | medium / exposure |
| AND-APP-001 | Android | stalkerware capability correlation (score ≥ 6 with a privileged/stealth signal) | high / suspicious (never confirmed) |
| AND-APP-002 | Android | side-loaded app with SMS/call-log/mic/background-location | low / to verify |
| AND-APP-003 | Android | debuggable third-party app | low / exposure |
| AND-APP-004 | Android | app allowed to install apps | low / exposure |
| AND-IOC-001 | Android | package or signing-cert IOC match | critical / confirmed (cert) or suspicious (package) |
| AND-MIC-001 | Android | summary of apps holding microphone permission | low / to verify |
| AND-LOC-001 | Android | background location granted | medium |
| NET-001…005 | both / Android | proxy, VPN, open/WEP Wi-Fi, captive portal, private DNS off | medium |
| NET-TLS-001 | both | certificate validation failure on well-known hosts (opt-in) | high / suspicious |
| IOS-CFG-001/002 | iOS | no passcode, outdated major version | high / exposure |
| IOS-INT-001/002 | iOS | jailbreak indicators, debugger attached | high / exposure |
| TRK-001 | both | BLE tracker seen (persistent across ≥ 30 min ⇒ medium) | medium / to verify |
| PHI-001 | both | link checked by user scored high risk / known bad | high |
| APK-* | Android | APK IOC, capability set, SMS fraud, debuggable, old target, unsigned, embedded payload, YARA matches | critical / confirmed only for hash/cert/signature rules |

## Adding a rule
1. Implement `DetectionRule`, add it to `androidRules` or `commonRules`.
2. Add positive **and** false-positive tests in `test/detection_rules_test.dart` using fixtures in `test/fixtures.dart`.
3. `flutter test` — the catalogue test enforces unique ids and documented confidence model / false positives.

## Publishing a signed pack
```
cd app && dart run tool/sign_rulepack.dart --generate        # once; keep the SEED secret
SENTINEL_RULES_SIGNING_SEED=<seed> dart run tool/sign_rulepack.dart assets/rules/rulepack.json
```
or `POST /v1/admin/rules/publish` on the backend (signs with the same seed from its environment). Add new public keys to `trustedRuleSigningKeys` *before* rotating.
