# Threat model (STRIDE)

## Assets
Security telemetry (installed apps, findings, incidents — highly sensitive: reveals e.g. a victim's suspicion of stalkerware), rule-pack integrity, backend device tokens, provider API keys, rule-signing key.

## Trust boundaries
1. App ↔ OS APIs (native plugin). 2. App ↔ local storage. 3. App ↔ backend (HTTPS). 4. Backend ↔ third-party reputation providers. 5. Rule pack publisher ↔ devices.

| STRIDE | Threat | Mitigation | Residual risk |
|---|---|---|---|
| **S**poofing | Fake backend serves malicious rules | Rule packs verified with pinned Ed25519 keys before use; HTTPS only; user CAs not trusted by the app | Compromise of the signing seed |
| S | Attacker uses another device's token | 256-bit random tokens, stored as SHA-256, constant-time compare | Token theft from a rooted device |
| **T**ampering | Local results edited to hide a finding | AES-256-GCM with per-document AAD; tampering ⇒ document discarded and error surfaced | Root attacker with key access |
| T | Rule-pack rollback to older version | `minimumVersion` persisted; older signed packs refused | — |
| T | Malicious app hides from inventory | Correlation of several signals; coverage shows limited visibility | Root-level malware can hide entirely |
| **R**epudiation | Admin changes providers/rules without trace | Audit log for registration, provider toggles, indicator imports, rule publishing, role changes | Log retention policy is operator-defined |
| **I**nformation disclosure | Telemetry leaked via backups | `allowBackup=false`, data-extraction exclusions, Keychain `ThisDeviceOnly` | — |
| I | Telemetry sent to third parties | Off by default; domains sent as SHA-256 hashes; files never uploaded; full URLs only with a second opt-in; provider keys only server-side | Backend operator sees hashes/URLs it receives |
| I | IDOR on synced incidents | Every incident query filtered by authenticated device id | — |
| I | Error messages echo sensitive URLs | Validation errors return field names only; generic 500 | — |
| I | Stalker notices the victim's scan | No server account by default; notifications are generic; guidance warns that uninstalling may alert the installer | Physical access to an unlocked phone |
| **D**enial of service | Reputation endpoint abuse | Per-device sliding-window rate limit, registration limit per IP, 256 KB body limit, provider timeouts | Distributed abuse (add proxy-level limits) |
| D | Huge APK / zip bomb | Entries > 64 MB skipped, analysis in background isolate | Very large archives slow the scan |
| **E**levation of privilege | Device token used for admin API | Role-based access (device < analyst < admin) enforced server-side; admin only via one-time bootstrap token | Bootstrap token left configured |
| E | App abused to perform destructive actions | App has no privileged permissions; all actions open OS UI requiring user confirmation | — |

## Abuse considerations
The app must not become a stalking tool: it never reveals another person's location, never records audio or calls, the tracker scan uses `neverForLocation`, and nothing is collected about third parties.

## OWASP MASVS mapping (summary)
STORAGE-1/2 (encrypted, no backups) · CRYPTO-1/2 (platform keystore, AES-GCM, Ed25519) · AUTH (backend tokens, RBAC) · NETWORK-1/2 (TLS only, no user CA trust, no cleartext) · PLATFORM-1/3 (minimal permissions, exported components limited to launcher + share) · CODE-1/4 (input validation in YARA/URL/rule parsers, R8) · RESILIENCE (root/jailbreak detection is informational, not a security boundary) · PRIVACY-1..4 (data minimisation, consent, deletion, transparency).
