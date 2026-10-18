# SENTINEL MOBILE SOC

SOC mobile personnel pour **Android** et **iOS** : évaluation de la posture de sécurité, détection d'indicateurs de malware / stalkerware, revue des accès privilégiés, appels & micro, pistage, réseau, hameçonnage, gestion d'incidents — avec des résultats **réels**, classés (confirmé / suspect / exposition / à vérifier), un niveau de confiance et la liste explicite de ce qui **n'a pas pu** être vérifié.

> Aucune application mobile ne peut garantir qu'un téléphone est sain. Sentinel n'affiche jamais « appareil totalement sûr ».

## Contenu du dépôt

| Dossier | Contenu |
|---|---|
| `app/` | Application Flutter (Dart) — UI FR/EN, moteur de détection, scoring, incidents, stockage chiffré |
| `app/packages/sentinel_native/` | Modules natifs **Kotlin** (Android) et **Swift** (iOS) — API publiques uniquement |
| `app/assets/rules/` | Pack de règles signé Ed25519 (indicateurs de **test** + règles YARA-lite) |
| `backend/` | API optionnelle FastAPI + PostgreSQL (réputation, règles signées, sync d'incidents, RBAC, audit) + Docker Compose |
| `docs/` | Architecture, matrice des capacités, modèle de menaces STRIDE, permissions, scoring, règles, confidentialité, tests, build, limites |
| `.github/workflows/` | CI : tests, APK Android, IPA iOS non signée (runner macOS), tests backend |

## Démarrage rapide

```bash
cd app
flutter pub get
flutter test                                   # 73 tests
flutter build apk --release --split-per-abi    # APK Android
flutter build ios --release --no-codesign      # iOS (sur macOS)
```

Installation sur téléphone et iPhone : voir [`docs/BUILD_RELEASE.md`](docs/BUILD_RELEASE.md) et le guide pas à pas [`docs/INSTALL_IPHONE.md`](docs/INSTALL_IPHONE.md).

## Documentation

- [Architecture](docs/ARCHITECTURE.md) · [Matrice Android/iOS](docs/CAPABILITY_MATRIX.md) · [Modèle de menaces](docs/THREAT_MODEL.md)
- [Permissions](docs/PERMISSIONS.md) · [Méthode de scoring](docs/SCORING.md) · [Règles de détection](docs/DETECTION_RULES.md)
- [Politique de confidentialité](docs/PRIVACY.md) · [Rapport de tests](docs/TESTING.md) · [Limites connues](docs/LIMITATIONS.md)

## Principes

- **Local d'abord** : fonctionne hors ligne ; aucun envoi de données sans consentement explicite (empreintes SHA-256 seulement par défaut).
- **Pas d'autorisations inutiles** : ni contacts, ni SMS, ni journal d'appels, ni micro. Bluetooth et notifications demandés uniquement à l'usage.
- **Jamais d'action silencieuse** : Sentinel ouvre l'écran système adéquat (réglages, désinstallation, composeur) ; l'utilisateur décide.
- **Transparence** : chaque résultat porte sa méthode de détection, ses preuves, ses limites et son niveau de confiance.
