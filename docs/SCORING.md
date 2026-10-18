# Security score methodology

The score answers "how much known, active risk did the last device scan observe?" — it is **not** a probability of infection and is never shown as "safe".

```
penalty(f)  = severity_weight × confidence_factor × classification_factor
category    = min(45, Σ penalty of active findings in that category)
score       = max(0, 100 − round(Σ categories))
```

| Severity | weight | | Confidence | factor | | Classification | factor |
|---|---|---|---|---|---|---|---|
| informational | 0 | | low | 0.4 | | confirmed malicious | 1.5 |
| low | 2 | | medium | 0.7 | | suspicious | 1.0 |
| medium | 6 | | high | 1.0 | | exposure | 1.0 |
| high | 15 | | | | | to verify (unverified) | 0.5 |
| critical | 30 | | | | | informational | 0 |

* Findings marked **resolved** or **false positive** by the user are excluded.
* The 45-point category cap stops one noisy area (e.g. many apps with background location) from zeroing the score alone.

## Posture

| Posture | Rule |
|---|---|
| Critical | any confirmed-malicious or critical finding, or score < 40 |
| At risk | any high-severity (non-informational) finding, or score < 70 |
| Fair | score < 85 |
| Strong | otherwise |
| Not assessed | no applicable check ran (e.g. collection failed) |

## Coverage

`coverage = checked / (applicable checks)` — every rule that could not run (API hidden, permission missing, platform restriction) and every manual-only surface (iOS app list, configuration profiles, call forwarding, other apps' microphone use) counts as *not checked*. Coverage is displayed next to the score; when no issue is found the UI says "No issues detected in the areas that could be checked (coverage N%)" and never "device is safe".

## Limitations

* Heuristic findings measure capability, not observed behaviour.
* The score only reflects the latest device scan; APK/link/tracker checks feed incidents but not the device score.
* Implemented in `app/lib/engine/scoring.dart`, covered by `test/engine_scoring_test.dart`.
