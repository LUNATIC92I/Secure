# Installer Sentinel Mobile SOC sur iPhone (version bêta de test)

L'application n'est pas encore sur l'App Store. Pendant la bêta, on l'installe soi‑même à partir du fichier `SentinelSOC-ios-unsigned.ipa`, signé avec **votre propre identifiant Apple** (gratuit).

## Ce qu'il vous faut

- Un iPhone sous **iOS 15 ou plus récent**
- Un ordinateur **Windows** ou **Mac**
- Un câble USB pour l'iPhone
- Un **identifiant Apple** (celui de l'iPhone convient ; un identifiant secondaire est encore mieux)
- Le fichier `SentinelSOC-ios-unsigned.ipa`

> ⚠️ Avec un identifiant Apple gratuit, l'app fonctionne **7 jours**, puis il faut la ré‑signer (2 minutes, voir plus bas). Vos données dans l'app sont conservées.

---

## Méthode 1 : Sideloadly (la plus simple)

### 1. Préparer l'ordinateur
- **Windows** : installez **iTunes** et **iCloud** depuis le site d'Apple (versions « hors Microsoft Store »), puis **Sideloadly** depuis sideloadly.io.
- **Mac** : installez **Sideloadly** depuis sideloadly.io.

### 2. Brancher l'iPhone
- Branchez l'iPhone par câble et déverrouillez‑le.
- Touchez **« Faire confiance »** sur l'iPhone si la question apparaît.

### 3. Installer l'app
1. Ouvrez Sideloadly. Votre iPhone apparaît dans la liste des appareils.
2. Glissez le fichier `SentinelSOC-ios-unsigned.ipa` dans la fenêtre.
3. Saisissez votre **identifiant Apple**, puis cliquez sur **Start**.
4. Entrez le mot de passe Apple, et le code à deux facteurs s'il est demandé.
5. Attendez le message **« Done »** (environ 1 minute).

### 4. Autoriser l'app sur l'iPhone
1. **Activer le mode développeur** (iOS 16 et plus récent) : ouvrez Réglages → Confidentialité et sécurité → **Mode développeur**, activez‑le, puis redémarrez l'iPhone et confirmez.
2. **Faire confiance au développeur** : ouvrez Réglages → Général → **VPN et gestion de l'appareil**. Touchez votre identifiant Apple, puis **Faire confiance**.
3. Lancez **Sentinel SOC** depuis l'écran d'accueil. ✅

---

## Méthode 2 : AltStore (renouvellement sans câble)

1. Sur l'ordinateur, installez **AltServer** depuis altstore.io (sous Windows, iTunes et iCloud sont aussi nécessaires).
2. Branchez l'iPhone, puis cliquez sur l'icône AltServer → **Install AltStore** → choisissez votre iPhone et saisissez votre identifiant Apple.
3. Sur l'iPhone, faites confiance au profil comme à l'étape 4 ci‑dessus, puis ouvrez **AltStore**.
4. Transférez le fichier `.ipa` sur l'iPhone, par AirDrop ou dans l'app Fichiers.
5. Dans AltStore → **Mes apps** → **+**, choisissez le fichier `.ipa`.

Avantage : AltStore renouvelle l'app automatiquement par Wi‑Fi tant qu'AltServer tourne sur l'ordinateur.

---

## Méthode 3 : Xcode (pour les développeurs, sur Mac)

1. Récupérez le code : `git clone https://github.com/LUNATIC92I/Secure`
2. Dans le dossier `app`, lancez `flutter pub get`, puis ouvrez `ios/Runner.xcworkspace` dans Xcode.
3. Ouvrez **Runner → Signing & Capabilities**, puis choisissez votre équipe (votre identifiant Apple).
4. Branchez l'iPhone, sélectionnez‑le, puis cliquez sur **▶︎ Run**.

---

## Renouveler l'app tous les 7 jours

Quand l'app ne s'ouvre plus, refaites simplement **l'étape 3 de la méthode 1** avec le même fichier, ou touchez **Actualiser** dans AltStore. Vous n'avez pas besoin de désinstaller l'app : vos résultats sont conservés.

---

## Problèmes fréquents

| Message / symptôme | Solution |
|---|---|
| « Développeur non approuvé » | Réglages → Général → VPN et gestion de l'appareil → **Faire confiance** |
| L'app se ferme immédiatement | Activez le **Mode développeur**, puis redémarrez |
| « Maximum number of apps » | Un identifiant gratuit est limité à 3 apps installées ainsi : supprimez‑en une |
| Sideloadly ne voit pas l'iPhone | Sous Windows, installez iTunes (version Apple), rebranchez l'iPhone et touchez « Faire confiance » |
| Erreur de mot de passe | Avec la double authentification, saisissez le code reçu ; essayez un identifiant secondaire |
| L'app ne s'ouvre plus après une semaine | C'est normal avec un compte gratuit : ré‑signez l'app (voir plus haut) |

---

## Ce que l'app peut et ne peut pas faire sur iPhone

iOS isole chaque application. Aucune app de l'App Store ne peut donc lister ou analyser les autres apps installées. Sur iPhone, Sentinel vérifie :

- ✅ le code de verrouillage, la version d'iOS et les indices de jailbreak
- ✅ un VPN ou un proxy actif
- ✅ les liens d'hameçonnage (collez un lien ou ouvrez `sentinel://scan?url=…`)
- ✅ les traceurs Bluetooth Tile, SmartTag et ceux du réseau Localiser mon appareil
  - les AirTags restent détectés par les alertes de suivi intégrées à iOS
- ✅ les incidents et les rapports

Pour le reste, l'app vous guide vers les outils intégrés d'iOS :

- **Contrôle de sécurité**
- **Rapport de confidentialité des apps**
- **VPN et gestion de l'appareil** (profils inconnus)

## Sécurité

- N'installez le fichier `.ipa` **que depuis le lien officiel** du projet.
- Méfiez‑vous des sites qui proposent d'installer des apps « sans ordinateur » avec des certificats d'entreprise : c'est un vecteur connu de malwares.
- Sentinel ne demande **jamais** vos contacts, SMS, appels ni l'accès au micro.

Un souci ? Envoyez une capture d'écran du message d'erreur et le modèle de votre iPhone.
