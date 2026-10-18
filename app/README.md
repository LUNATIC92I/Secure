# Sentinel Mobile SOC — Flutter app

See the repository [README](../README.md) and [docs/](../docs). Layout:

- `lib/core` models, snapshot, incidents, settings · `lib/detection` rules, rule pack, YARA-lite
- `lib/engine` scan engine, scoring, URL/APK analysers, network probe, trackers · `lib/intel` threat-intel layer
- `lib/services` encrypted store, repository, notifications, background scheduler · `lib/state` AppState · `lib/ui` screens
- `packages/sentinel_native` Kotlin/Swift bridge · `tool/sign_rulepack.dart` rule-pack signing
