import '../core/models.dart';
import '../core/snapshot.dart';
import 'permissions.dart';
import 'rule.dart';

const _android = {DevicePlatform.android};

const _settingsMethod = LText(
  'Read from documented Android Settings / system service APIs',
  'Lu via les API documentées Paramètres / services système Android',
);

// ------------------------------------------------------------------ configuration

class ScreenLockRule extends DetectionRule {
  const ScreenLockRule();
  @override
  String get id => 'AND-CFG-001';
  @override
  LText get name => const LText('Screen lock', 'Verrouillage de l’écran');
  @override
  LText get description => const LText('Detects devices without a PIN, pattern or password.', 'Détecte les appareils sans code, schéma ou mot de passe.');
  @override
  Set<DevicePlatform> get platforms => _android;
  @override
  LText get confidenceModel => const LText('High: KeyguardManager.isDeviceSecure is authoritative.', 'Élevée : KeyguardManager.isDeviceSecure fait foi.');
  @override
  LText get knownFalsePositives => const LText('None known.', 'Aucun connu.');
  @override
  bool available(RuleContext ctx) => ctx.snapshot.d<bool>('deviceSecure') != null;

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    if (ctx.snapshot.d<bool>('deviceSecure') == false) {
      yield finding(
        ctx,
        title: const LText('No secure screen lock', 'Aucun verrouillage sécurisé'),
        description: const LText(
          'Anyone holding the phone can open it, install monitoring apps or read your data. A screen lock is also what protects the encryption keys.',
          'Toute personne ayant le téléphone en main peut l’ouvrir, installer une app de surveillance ou lire vos données. Le verrouillage protège aussi les clés de chiffrement.',
        ),
        severity: Severity.high,
        confidence: Confidence.high,
        classification: Classification.exposure,
        category: FindingCategory.configuration,
        method: _settingsMethod,
        limitations: const LText('Does not assess PIN strength.', 'N’évalue pas la robustesse du code.'),
        evidence: {'KeyguardManager.isDeviceSecure': 'false'},
        remediation: [Steps.settings('security', 'Set a PIN, pattern or password', 'Définir un code, schéma ou mot de passe')],
      );
    }
  }
}

class EncryptionRule extends DetectionRule {
  const EncryptionRule();
  @override
  String get id => 'AND-CFG-002';
  @override
  LText get name => const LText('Storage encryption', 'Chiffrement du stockage');
  @override
  LText get description => const LText('Checks DevicePolicyManager storage encryption status.', 'Vérifie l’état de chiffrement via DevicePolicyManager.');
  @override
  Set<DevicePlatform> get platforms => _android;
  @override
  LText get confidenceModel => const LText('High when status is reported; skipped when "unknown".', 'Élevée si l’état est rapporté ; ignorée si « inconnu ».');
  @override
  LText get knownFalsePositives => const LText(
    '"defaultKey" is reported on devices encrypted without a lock-screen secret.',
    '« defaultKey » est signalé sur les appareils chiffrés sans secret de verrouillage.',
  );

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    final s = ctx.snapshot.d<String>('encryptionStatus');
    if (s == 'inactive' || s == 'unsupported' || s == 'defaultKey') {
      yield finding(
        ctx,
        title: s == 'defaultKey'
            ? const LText('Encryption not bound to your lock screen', 'Chiffrement non lié au verrouillage')
            : const LText('Storage is not encrypted', 'Stockage non chiffré'),
        description: const LText(
          'Data could be read by someone with physical access to the device.',
          'Les données pourraient être lues par une personne ayant un accès physique à l’appareil.',
        ),
        severity: s == 'defaultKey' ? Severity.medium : Severity.high,
        confidence: Confidence.high,
        classification: Classification.exposure,
        category: FindingCategory.configuration,
        method: _settingsMethod,
        limitations: const LText('Reported by the OS; vendor builds may differ.', 'Rapporté par l’OS ; peut varier selon le constructeur.'),
        evidence: {'storageEncryptionStatus': s!},
        remediation: [Steps.settings('security', 'Enable a screen lock and encryption', 'Activer le verrouillage et le chiffrement')],
      );
    }
  }
}

class AdbRule extends DetectionRule {
  const AdbRule();
  @override
  String get id => 'AND-CFG-003';
  @override
  LText get name => const LText('USB debugging', 'Débogage USB');
  @override
  LText get description => const LText(
    'USB debugging lets a connected computer install apps and read data.',
    'Le débogage USB permet à un ordinateur connecté d’installer des apps et de lire des données.',
  );
  @override
  Set<DevicePlatform> get platforms => _android;
  @override
  LText get confidenceModel => const LText('High: Settings.Global.ADB_ENABLED.', 'Élevée : Settings.Global.ADB_ENABLED.');
  @override
  LText get knownFalsePositives => const LText('Expected on developer phones.', 'Normal sur un téléphone de développeur.');

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    if (ctx.snapshot.d<bool>('adbEnabled') == true) {
      yield finding(
        ctx,
        title: const LText('USB debugging is enabled', 'Le débogage USB est activé'),
        description: description,
        severity: Severity.medium,
        confidence: Confidence.high,
        classification: Classification.exposure,
        category: FindingCategory.configuration,
        method: _settingsMethod,
        limitations: const LText('Cannot tell which computers were authorised.', 'Impossible de savoir quels ordinateurs ont été autorisés.'),
        evidence: {'adb_enabled': '1'},
        remediation: [
          Steps.settings(
            'developer',
            'Turn off USB debugging and revoke USB debugging authorisations',
            'Désactiver le débogage USB et révoquer les autorisations',
          ),
        ],
      );
    }
  }
}

class DeveloperOptionsRule extends DetectionRule {
  const DeveloperOptionsRule();
  @override
  String get id => 'AND-CFG-004';
  @override
  LText get name => const LText('Developer options', 'Options pour les développeurs');
  @override
  LText get description => const LText(
    'Developer options expose settings that weaken security when misused.',
    'Les options développeur exposent des réglages qui affaiblissent la sécurité.',
  );
  @override
  Set<DevicePlatform> get platforms => _android;
  @override
  LText get confidenceModel => const LText('High: Settings.Global.DEVELOPMENT_SETTINGS_ENABLED.', 'Élevée : Settings.Global.DEVELOPMENT_SETTINGS_ENABLED.');
  @override
  LText get knownFalsePositives => const LText('Expected on developer phones.', 'Normal sur un téléphone de développeur.');

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    if (ctx.snapshot.d<bool>('developerOptions') == true) {
      yield finding(
        ctx,
        title: const LText('Developer options are enabled', 'Options développeur activées'),
        description: description,
        severity: Severity.low,
        confidence: Confidence.high,
        classification: Classification.exposure,
        category: FindingCategory.configuration,
        method: _settingsMethod,
        limitations: const LText('Individual developer settings are not inspected.', 'Les réglages individuels ne sont pas inspectés.'),
        evidence: {'development_settings_enabled': '1'},
        remediation: [Steps.settings('developer', 'Turn off developer options if you do not need them', 'Désactiver les options si inutiles')],
      );
    }
  }
}

class PatchLevelRule extends DetectionRule {
  const PatchLevelRule();
  @override
  String get id => 'AND-CFG-005';
  @override
  LText get name => const LText('Security patch level', 'Niveau de correctif de sécurité');
  @override
  LText get description => const LText('Flags devices whose security patch is old.', 'Signale un correctif de sécurité ancien.');
  @override
  Set<DevicePlatform> get platforms => _android;
  @override
  LText get confidenceModel => const LText(
    'High: Build.VERSION.SECURITY_PATCH; thresholds come from the rule pack.',
    'Élevée : Build.VERSION.SECURITY_PATCH ; seuils issus du pack de règles.',
  );
  @override
  LText get knownFalsePositives =>
      const LText('Some vendors back-port fixes without bumping the date.', 'Certains constructeurs intègrent des correctifs sans changer la date.');

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    final raw = ctx.snapshot.d<String>('securityPatch');
    final patch = raw == null ? null : DateTime.tryParse(raw);
    if (patch == null) return;
    final age = ctx.now.difference(patch).inDays;
    final warn = ctx.pack.cfgInt('androidPatchWarnDays', 90);
    final crit = ctx.pack.cfgInt('androidPatchCriticalDays', 365);
    if (age < warn) return;
    yield finding(
      ctx,
      title: LText('Security patch is $age days old', 'Correctif de sécurité vieux de $age jours'),
      description: const LText(
        'Older patch levels leave publicly known vulnerabilities unfixed, some of which are used by commercial spyware.',
        'Un correctif ancien laisse des vulnérabilités publiques non corrigées, dont certaines sont exploitées par des logiciels espions commerciaux.',
      ),
      severity: age >= crit ? Severity.high : Severity.medium,
      confidence: Confidence.high,
      classification: Classification.exposure,
      category: FindingCategory.configuration,
      method: _settingsMethod,
      limitations: const LText(
        'The device may no longer receive updates from its manufacturer.',
        'L’appareil peut ne plus recevoir de mises à jour du constructeur.',
      ),
      evidence: {'securityPatch': raw!, 'ageDays': '$age'},
      remediation: [
        Steps.settings('systemUpdate', 'Check for system updates', 'Rechercher les mises à jour système'),
        Steps.advice(
          'If no update is available, consider a device that still receives security updates.',
          'Si aucune mise à jour n’est disponible, envisagez un appareil encore suivi.',
        ),
      ],
    );
  }
}

class OsVersionRule extends DetectionRule {
  const OsVersionRule();
  @override
  String get id => 'AND-CFG-006';
  @override
  LText get name => const LText('Android version support', 'Version d’Android');
  @override
  LText get description => const LText('Flags Android versions older than the rule pack minimum.', 'Signale une version d’Android antérieure au minimum.');
  @override
  Set<DevicePlatform> get platforms => _android;
  @override
  LText get confidenceModel => const LText('High: Build.VERSION.SDK_INT.', 'Élevée : Build.VERSION.SDK_INT.');
  @override
  LText get knownFalsePositives => const LText('None.', 'Aucun.');

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    final sdk = (ctx.snapshot.device['sdkInt'] as num?)?.toInt();
    final min = ctx.pack.cfgInt('androidMinSupportedSdk', 31);
    if (sdk != null && sdk < min) {
      yield finding(
        ctx,
        title: LText('Android ${ctx.snapshot.d<String>('osVersion')} is outdated', 'Android ${ctx.snapshot.d<String>('osVersion')} est obsolète'),
        description: const LText(
          'Older Android releases lack newer privacy protections (permission auto-reset, privacy indicators, restricted settings).',
          'Les anciennes versions n’ont pas les protections récentes (réinitialisation des autorisations, indicateurs de confidentialité, paramètres restreints).',
        ),
        severity: Severity.medium,
        confidence: Confidence.high,
        classification: Classification.exposure,
        category: FindingCategory.configuration,
        method: _settingsMethod,
        limitations: const LText('Minimum version is a policy choice set in the rule pack.', 'Le minimum est un choix défini dans le pack.'),
        evidence: {'sdkInt': '$sdk', 'minimum': '$min'},
        remediation: [Steps.settings('systemUpdate', 'Check for system updates', 'Rechercher les mises à jour système')],
      );
    }
  }
}

// ------------------------------------------------------------------ integrity

class RootRule extends DetectionRule {
  const RootRule();
  @override
  String get id => 'AND-INT-001';
  @override
  LText get name => const LText('Root indicators', 'Indicateurs de root');
  @override
  LText get description =>
      const LText('Looks for su binaries, root managers and test-keys builds.', 'Recherche des binaires su, gestionnaires de root et builds test-keys.');
  @override
  Set<DevicePlatform> get platforms => _android;
  @override
  LText get confidenceModel => const LText(
    'Medium for su/manager presence, low for test-keys only. Hidden root (e.g. Magisk DenyList) is not detectable.',
    'Moyenne pour su/gestionnaire, faible pour test-keys seul. Un root masqué n’est pas détectable.',
  );
  @override
  LText get knownFalsePositives => const LText(
    'Custom ROMs signed with test keys; intentionally rooted phones.',
    'ROM personnalisées signées test-keys ; téléphones rootés volontairement.',
  );

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    final root = (ctx.snapshot.device['root'] as Map?) ?? const {};
    final su = (root['suPaths'] as List?)?.cast<Object?>() ?? const [];
    final managers = (root['rootManagers'] as List?)?.cast<Object?>() ?? const [];
    final testKeys = root['testKeys'] == true;
    if (su.isEmpty && managers.isEmpty && !testKeys) return;
    final strong = su.isNotEmpty || managers.isNotEmpty;
    yield finding(
      ctx,
      title: strong
          ? const LText('Device appears to be rooted', 'L’appareil semble rooté')
          : const LText('Build signed with test keys', 'Build signé avec des clés de test'),
      description: const LText(
        'Root access removes Android’s app isolation: any app granted root can read other apps’ data, hide itself or record calls. Rooting does not mean the device is infected.',
        'Le root supprime l’isolation des applications : une app ayant le root peut lire les données des autres, se cacher ou enregistrer les appels. Rooté ne veut pas dire infecté.',
      ),
      severity: strong ? Severity.high : Severity.medium,
      confidence: strong ? Confidence.medium : Confidence.low,
      classification: Classification.exposure,
      category: FindingCategory.integrity,
      method: const LText('File-existence checks, package lookup and Build.TAGS', 'Vérification de fichiers, recherche de paquets et Build.TAGS'),
      limitations: const LText(
        'Root can be hidden from apps; absence of indicators is not proof of integrity.',
        'Le root peut être masqué ; l’absence d’indicateurs ne prouve pas l’intégrité.',
      ),
      evidence: {
        if (su.isNotEmpty) 'suPaths': su.join(', '),
        if (managers.isNotEmpty) 'rootManagers': managers.join(', '),
        'buildTags': '${ctx.snapshot.d<String>('buildTags')}',
      },
      remediation: [
        Steps.advice(
          'If you did not root this phone yourself, back up your data and reflash the official firmware or factory reset.',
          'Si vous n’avez pas rooté ce téléphone, sauvegardez puis réinstallez le firmware officiel ou réinitialisez.',
        ),
        Steps.passwordsFromTrustedDevice,
      ],
    );
  }
}

class BootStateRule extends DetectionRule {
  const BootStateRule();
  @override
  String get id => 'AND-INT-002';
  @override
  LText get name => const LText('Verified boot / bootloader', 'Démarrage vérifié / bootloader');
  @override
  LText get description => const LText(
    'Reads the verified boot state and bootloader lock flag where exposed.',
    'Lit l’état du démarrage vérifié et du verrouillage du bootloader s’ils sont exposés.',
  );
  @override
  Set<DevicePlatform> get platforms => _android;
  @override
  LText get confidenceModel => const LText(
    'Medium: values come from system properties, which some vendors hide or spoof.',
    'Moyenne : valeurs issues de propriétés système, parfois masquées.',
  );
  @override
  LText get knownFalsePositives => const LText('Devices unlocked on purpose by their owner.', 'Appareils déverrouillés volontairement.');
  @override
  bool available(RuleContext ctx) => ctx.snapshot.probeAvailable('bootProps');
  @override
  LText get coverageLabel => name;

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    final props = (ctx.snapshot.device['bootProps'] as Map?) ?? const {};
    final vb = props['ro.boot.verifiedbootstate'] as String?;
    final locked = props['ro.boot.flash.locked'] as String?;
    final state = props['ro.boot.vbmeta.device_state'] as String?;
    final unlocked = vb == 'orange' || locked == '0' || state == 'unlocked';
    final yellow = vb == 'yellow';
    if (!unlocked && !yellow) return;
    yield finding(
      ctx,
      title: unlocked
          ? const LText('Bootloader is unlocked', 'Le bootloader est déverrouillé')
          : const LText('Custom verified-boot key', 'Clé de démarrage vérifié personnalisée'),
      description: const LText(
        'An unlocked bootloader allows modified system software to run without warning, which defeats several Android protections.',
        'Un bootloader déverrouillé permet d’exécuter un système modifié sans avertissement, ce qui annule plusieurs protections.',
      ),
      severity: unlocked ? Severity.high : Severity.medium,
      confidence: Confidence.medium,
      classification: Classification.exposure,
      category: FindingCategory.integrity,
      method: const LText('getprop system properties', 'Propriétés système via getprop'),
      limitations: const LText(
        'Play Integrity attestation gives a stronger signal and requires a backend (not configured by default).',
        'L’attestation Play Integrity est plus fiable et nécessite un serveur (non configuré par défaut).',
      ),
      evidence: {'verifiedbootstate': '$vb', 'flash.locked': '$locked', 'vbmeta.device_state': '$state'},
      remediation: [
        Steps.advice(
          'If you did not unlock it, restore official firmware and re-lock the bootloader.',
          'Si vous ne l’avez pas déverrouillé, restaurez le firmware officiel et reverrouillez le bootloader.',
        ),
      ],
    );
  }
}

class EmulatorRule extends DetectionRule {
  const EmulatorRule();
  @override
  String get id => 'AND-INT-003';
  @override
  LText get name => const LText('Emulator detection', 'Détection d’émulateur');
  @override
  LText get description => const LText('Informs that results come from an emulator.', 'Indique que les résultats proviennent d’un émulateur.');
  @override
  Set<DevicePlatform> get platforms => _android;
  @override
  LText get confidenceModel => const LText('Medium: Build fingerprint heuristics.', 'Moyenne : heuristique sur Build.');
  @override
  LText get knownFalsePositives => const LText('Rare custom ROMs with generic fingerprints.', 'Rares ROM au fingerprint générique.');

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    if (ctx.snapshot.d<bool>('isEmulator') == true) {
      yield finding(
        ctx,
        title: const LText('Running on an emulator', 'Exécution sur un émulateur'),
        description: const LText(
          'Some checks behave differently on emulators (root, boot state, Wi-Fi).',
          'Certaines vérifications diffèrent sur émulateur (root, démarrage, Wi-Fi).',
        ),
        severity: Severity.informational,
        confidence: Confidence.medium,
        classification: Classification.informational,
        category: FindingCategory.integrity,
        method: const LText('Build.FINGERPRINT / HARDWARE', 'Build.FINGERPRINT / HARDWARE'),
        limitations: const LText('Heuristic.', 'Heuristique.'),
        evidence: {'fingerprint': '${ctx.snapshot.d<String>('fingerprint')}'},
      );
    }
  }
}

// ------------------------------------------------------------------ privileged access

class AccessibilityRule extends DetectionRule {
  const AccessibilityRule();
  @override
  String get id => 'AND-ACC-001';
  @override
  LText get name => const LText('Accessibility services', 'Services d’accessibilité');
  @override
  LText get description => const LText(
    'Lists enabled third-party accessibility services, the main capability abused by banking trojans and stalkerware.',
    'Liste les services d’accessibilité tiers activés, principale capacité abusée par les chevaux de Troie bancaires et stalkerwares.',
  );
  @override
  Set<DevicePlatform> get platforms => _android;
  @override
  LText get confidenceModel => const LText(
    'High that the service is enabled; suspicion raised to medium when the app is also side-loaded or hidden from the launcher.',
    'Élevée sur l’activation ; suspicion moyenne si l’app est aussi installée hors store ou masquée.',
  );
  @override
  LText get knownFalsePositives => const LText(
    'Password managers, screen readers, automation and launcher apps legitimately use accessibility.',
    'Gestionnaires de mots de passe, lecteurs d’écran, automatisation et lanceurs l’utilisent légitimement.',
  );

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    for (final s in ctx.snapshot.list('accessibilityServices')) {
      if (s['isSystem'] == true) continue;
      final pkg = s['package'] as String?;
      final app = ctx.snapshot.app(pkg);
      final sideloaded = app?.isSideloaded ?? false;
      final hidden = app != null && !app.hasLauncher;
      final elevated = sideloaded || hidden;
      yield finding(
        ctx,
        component: pkg,
        componentLabel: ctx.snapshot.labelFor(pkg),
        title: LText('Accessibility access: ${ctx.snapshot.labelFor(pkg)}', 'Accès accessibilité : ${ctx.snapshot.labelFor(pkg)}'),
        description: const LText(
          'This app can read everything on screen (including messages and passwords as you type) and perform taps on your behalf. Make sure you installed it and need this access.',
          'Cette app peut lire tout l’écran (y compris messages et mots de passe saisis) et effectuer des actions à votre place. Vérifiez que vous l’avez installée et que cet accès est nécessaire.',
        ),
        severity: elevated ? Severity.high : Severity.medium,
        confidence: elevated ? Confidence.medium : Confidence.high,
        classification: elevated ? Classification.suspicious : Classification.unverified,
        category: FindingCategory.permissions,
        method: const LText('AccessibilityManager.getEnabledAccessibilityServiceList', 'AccessibilityManager.getEnabledAccessibilityServiceList'),
        limitations: const LText('Cannot see what the service actually does.', 'Impossible de voir ce que fait réellement le service.'),
        evidence: {
          'service': '${s['id']}',
          'canRetrieveWindowContent': '${s['canRetrieveWindowContent']}',
          'canPerformGestures': '${s['canPerformGestures']}',
          if (app != null) 'installer': app.installer ?? 'unknown',
          if (hidden) 'launcherIcon': 'none',
        },
        remediation: [
          Steps.settings(
            'accessibility',
            'Turn off this accessibility service if you do not recognise it',
            'Désactiver ce service si vous ne le reconnaissez pas',
          ),
          if (pkg != null) Steps.uninstall(pkg),
        ],
      );
    }
  }
}

class DeviceAdminRule extends DetectionRule {
  const DeviceAdminRule();
  @override
  String get id => 'AND-ADM-001';
  @override
  LText get name => const LText('Device administrators & management', 'Administrateurs et gestion de l’appareil');
  @override
  LText get description => const LText(
    'Lists active device-admin apps and device/profile owners (MDM).',
    'Liste les administrateurs actifs et propriétaires d’appareil/profil (MDM).',
  );
  @override
  Set<DevicePlatform> get platforms => _android;
  @override
  LText get confidenceModel =>
      const LText('High that admin rights are active (DevicePolicyManager.getActiveAdmins).', 'Élevée sur l’activation (DevicePolicyManager.getActiveAdmins).');
  @override
  LText get knownFalsePositives => const LText(
    'Work profiles, Find My Device, corporate MDM, parental-control apps you set up.',
    'Profil professionnel, Localiser mon appareil, MDM d’entreprise, contrôle parental que vous avez installé.',
  );

  static const _benign = {'com.google.android.gms', 'com.google.android.apps.work.clouddpc', 'com.samsung.android.knox.containercore'};

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    for (final a in ctx.snapshot.list('deviceAdmins')) {
      final pkg = a['package'] as String?;
      if (pkg == null || _benign.contains(pkg)) continue;
      final app = ctx.snapshot.app(pkg);
      if (app?.isSystem == true) continue;
      final owner = a['isDeviceOwner'] == true || a['isProfileOwner'] == true;
      final sideloaded = app?.isSideloaded ?? false;
      yield finding(
        ctx,
        component: pkg,
        componentLabel: ctx.snapshot.labelFor(pkg),
        title: owner
            ? LText('Device is managed by ${ctx.snapshot.labelFor(pkg)}', 'Appareil géré par ${ctx.snapshot.labelFor(pkg)}')
            : LText('Device-admin rights: ${ctx.snapshot.labelFor(pkg)}', 'Droits d’administrateur : ${ctx.snapshot.labelFor(pkg)}'),
        description: owner
            ? const LText(
                'A device/profile owner can install apps, read some activity and enforce policies. Expected only on work or school phones.',
                'Un propriétaire d’appareil/profil peut installer des apps, voir certaines activités et imposer des règles. Normal uniquement sur un téléphone professionnel ou scolaire.',
              )
            : const LText(
                'Device-admin apps can lock or wipe the phone and resist uninstallation; stalkerware uses this to protect itself.',
                'Une app administrateur peut verrouiller ou effacer le téléphone et résister à la désinstallation ; les stalkerwares l’utilisent pour se protéger.',
              ),
        severity: owner || sideloaded ? Severity.high : Severity.medium,
        confidence: Confidence.high,
        classification: sideloaded ? Classification.suspicious : Classification.unverified,
        category: FindingCategory.permissions,
        method: const LText('DevicePolicyManager.getActiveAdmins / isDeviceOwnerApp', 'DevicePolicyManager.getActiveAdmins / isDeviceOwnerApp'),
        limitations: const LText('Cannot read which policies the admin enforces.', 'Impossible de lire les règles imposées.'),
        evidence: {'component': '${a['component']}', 'deviceOwner': '${a['isDeviceOwner']}', 'profileOwner': '${a['isProfileOwner']}'},
        remediation: [
          Steps.settings(
            'deviceAdmin',
            'Deactivate the admin app if you do not recognise it, then uninstall it',
            'Désactiver l’administrateur si vous ne le reconnaissez pas, puis le désinstaller',
          ),
          if (owner)
            Steps.advice(
              'If this is not a work/school phone, a factory reset is the reliable way to remove a device owner.',
              'S’il ne s’agit pas d’un téléphone pro/scolaire, seule une réinitialisation retire fiablement un propriétaire d’appareil.',
            ),
        ],
      );
    }
  }
}

class NotificationListenerRule extends DetectionRule {
  const NotificationListenerRule();
  @override
  String get id => 'AND-NLS-001';
  @override
  LText get name => const LText('Notification access', 'Accès aux notifications');
  @override
  LText get description => const LText(
    'Apps with notification access can read every notification, including messages and 2FA codes.',
    'Les apps avec accès aux notifications lisent toutes les notifications, y compris messages et codes 2FA.',
  );
  @override
  Set<DevicePlatform> get platforms => _android;
  @override
  LText get confidenceModel => const LText(
    'High when Android exposes the list; on some versions it is hidden (reported as unavailable).',
    'Élevée si Android expose la liste ; masquée sur certaines versions.',
  );
  @override
  LText get knownFalsePositives => const LText(
    'Smartwatch companions, car integrations, notification history apps.',
    'Applications de montre, intégrations auto, historique de notifications.',
  );
  @override
  bool available(RuleContext ctx) => ctx.snapshot.device['notificationListeners'] != null;

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    final list = (ctx.snapshot.device['notificationListeners'] as List?)?.cast<Object?>() ?? const [];
    for (final c in list) {
      final pkg = '$c'.split('/').first;
      final app = ctx.snapshot.app(pkg);
      if (app?.isSystem == true) continue;
      final sideloaded = app?.isSideloaded ?? false;
      yield finding(
        ctx,
        component: pkg,
        componentLabel: ctx.snapshot.labelFor(pkg),
        title: LText('Notification access: ${ctx.snapshot.labelFor(pkg)}', 'Accès aux notifications : ${ctx.snapshot.labelFor(pkg)}'),
        description: description,
        severity: sideloaded ? Severity.high : Severity.medium,
        confidence: Confidence.high,
        classification: sideloaded ? Classification.suspicious : Classification.unverified,
        category: FindingCategory.permissions,
        method: const LText('Settings.Secure enabled_notification_listeners', 'Settings.Secure enabled_notification_listeners'),
        limitations: const LText('Cannot see which notifications were read.', 'Impossible de voir quelles notifications ont été lues.'),
        evidence: {'component': '$c'},
        remediation: [Steps.settings('notificationListeners', 'Revoke notification access if not needed', 'Révoquer l’accès si inutile')],
      );
    }
  }
}

class KeyboardRule extends DetectionRule {
  const KeyboardRule();
  @override
  String get id => 'AND-IME-001';
  @override
  LText get name => const LText('Third-party keyboard', 'Clavier tiers');
  @override
  LText get description => const LText('The default keyboard sees everything you type.', 'Le clavier par défaut voit tout ce que vous tapez.');
  @override
  Set<DevicePlatform> get platforms => _android;
  @override
  LText get confidenceModel => const LText('High that the keyboard is active.', 'Élevée sur l’activation.');
  @override
  LText get knownFalsePositives =>
      const LText('Popular keyboards from app stores are generally fine.', 'Les claviers populaires des stores sont généralement sûrs.');

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    final id = ctx.snapshot.d<String>('defaultInputMethod');
    if (id == null) return;
    final pkg = id.split('/').first;
    final ime = ctx.snapshot.list('inputMethods').where((m) => m['package'] == pkg).firstOrNull;
    if (ime == null || ime['isSystem'] == true) return;
    final app = ctx.snapshot.app(pkg);
    final sideloaded = app?.isSideloaded ?? false;
    yield finding(
      ctx,
      component: pkg,
      componentLabel: ctx.snapshot.labelFor(pkg),
      title: LText('Default keyboard: ${ctx.snapshot.labelFor(pkg)}', 'Clavier par défaut : ${ctx.snapshot.labelFor(pkg)}'),
      description: description,
      severity: sideloaded ? Severity.high : Severity.low,
      confidence: Confidence.high,
      classification: sideloaded ? Classification.suspicious : Classification.informational,
      category: FindingCategory.privacy,
      method: const LText('Settings.Secure default_input_method', 'Settings.Secure default_input_method'),
      limitations: const LText('Keyboard behaviour is not analysed.', 'Le comportement du clavier n’est pas analysé.'),
      evidence: {'inputMethod': id, if (app != null) 'installer': app.installer ?? 'unknown'},
      remediation: [Steps.settings('inputMethods', 'Review keyboards', 'Vérifier les claviers')],
    );
  }
}

class UserCaRule extends DetectionRule {
  const UserCaRule();
  @override
  String get id => 'AND-NET-001';
  @override
  LText get name => const LText('User-installed CA certificates', 'Certificats CA installés par l’utilisateur');
  @override
  LText get description => const LText(
    'A user CA can let someone intercept encrypted traffic of apps that trust user CAs.',
    'Un CA utilisateur peut permettre d’intercepter le trafic chiffré des apps qui font confiance aux CA utilisateur.',
  );
  @override
  Set<DevicePlatform> get platforms => _android;
  @override
  LText get confidenceModel => const LText('High that the certificate is installed.', 'Élevée sur la présence du certificat.');
  @override
  LText get knownFalsePositives =>
      const LText('Corporate Wi-Fi, debugging proxies, some antivirus web shields.', 'Wi-Fi d’entreprise, proxys de débogage, certains antivirus.');
  @override
  bool available(RuleContext ctx) => ctx.snapshot.device['userCaCertificates'] != null;

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    for (final c in ctx.snapshot.list('userCaCertificates')) {
      yield finding(
        ctx,
        component: c['sha256'] as String?,
        componentLabel: '${c['subject']}',
        title: LText('User CA certificate: ${_cn(c['subject'])}', 'Certificat CA utilisateur : ${_cn(c['subject'])}'),
        description: const LText(
          'Since Android 7 most apps ignore user CAs, but browsers and apps that opt in can have their HTTPS traffic decrypted by whoever holds this certificate’s key.',
          'Depuis Android 7 la plupart des apps ignorent ces CA, mais les navigateurs et apps qui les acceptent peuvent voir leur HTTPS déchiffré par le détenteur de la clé.',
        ),
        severity: Severity.medium,
        confidence: Confidence.high,
        classification: Classification.exposure,
        category: FindingCategory.network,
        method: const LText('AndroidCAStore keystore ("user:" aliases)', 'Keystore AndroidCAStore (alias « user: »)'),
        limitations: const LText(
          'Cannot tell who installed it or whether traffic is being intercepted.',
          'Impossible de savoir qui l’a installé ou si du trafic est intercepté.',
        ),
        evidence: {'subject': '${c['subject']}', 'issuer': '${c['issuer']}', 'sha256': '${c['sha256']}'},
        remediation: [
          Steps.settings(
            'credentials',
            'Remove the certificate if you do not recognise it (Trusted credentials → User)',
            'Supprimer le certificat si inconnu (Identifiants de confiance → Utilisateur)',
          ),
        ],
      );
    }
  }

  static String _cn(Object? dn) => RegExp(r'CN=([^,]+)').firstMatch('$dn')?.group(1) ?? '$dn';
}

// ------------------------------------------------------------------ apps

/// Correlates independent capabilities typical of stalkerware. Each signal alone is common;
/// several together, on a side-loaded or hidden app, are what monitoring tools look like.
class StalkerwareCorrelationRule extends DetectionRule {
  const StalkerwareCorrelationRule();
  @override
  String get id => 'AND-APP-001';
  @override
  int get version => 2;
  @override
  LText get name => const LText('Stalkerware behaviour correlation', 'Corrélation de comportements stalkerware');
  @override
  LText get description => const LText(
    'Scores each non-system app on: side-loading, hidden launcher icon, accessibility, device admin, notification access, and granted surveillance permissions.',
    'Évalue chaque app non système : installation hors store, icône masquée, accessibilité, administrateur, accès notifications et autorisations de surveillance accordées.',
  );
  @override
  Set<DevicePlatform> get platforms => _android;
  @override
  Set<Capability> get requires => const {Capability.appInventory};
  @override
  LText get confidenceModel => const LText(
    'Score ≥ 9 → high severity / medium confidence; 6-8 → medium / low. Never "confirmed".',
    'Score ≥ 9 → gravité élevée / confiance moyenne ; 6-8 → moyenne / faible. Jamais « confirmé ».',
  );
  @override
  LText get knownFalsePositives => const LText(
    'Parental-control and anti-theft apps intentionally installed; enterprise tools.',
    'Contrôle parental et antivol installés volontairement ; outils d’entreprise.',
  );
  @override
  bool available(RuleContext ctx) => ctx.snapshot.appInventorySupported;

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    final accessibility = ctx.snapshot.list('accessibilityServices').map((s) => s['package']).toSet();
    final admins = ctx.snapshot.list('deviceAdmins').map((s) => s['package']).toSet();
    final listeners = ((ctx.snapshot.device['notificationListeners'] as List?) ?? const []).map((c) => '$c'.split('/').first).toSet();

    for (final app in ctx.snapshot.apps) {
      if (app.isSystem) continue;
      final signals = <String, int>{};
      if (app.isSideloaded) signals['installedOutsideStore'] = 2;
      if (!app.hasLauncher) signals['noLauncherIcon'] = 2;
      if (accessibility.contains(app.package)) signals['accessibilityEnabled'] = 3;
      if (admins.contains(app.package)) signals['deviceAdmin'] = 2;
      if (listeners.contains(app.package)) signals['notificationAccess'] = 2;
      if (app.appOps['usageStats'] == 'allowed') signals['usageAccess'] = 1;
      if (app.appOps['overlay'] == 'allowed') signals['drawOverApps'] = 1;
      var permScore = 0;
      final groups = <String>{};
      for (final p in app.grantedPermissions) {
        final s = sensitiveByName[p];
        if (s != null && groups.add(s.group)) permScore += s.weight;
      }
      if (permScore > 0) signals['surveillancePermissions(${groups.join('+')})'] = permScore.clamp(0, 6);
      final total = signals.values.fold<int>(0, (a, b) => a + b);
      // Require at least one stealth/privilege signal so ordinary messaging apps do not trigger.
      final privileged = signals.keys.any((k) => const {'noLauncherIcon', 'accessibilityEnabled', 'deviceAdmin', 'notificationAccess'}.contains(k));
      if (total < 6 || !privileged) continue;
      final high = total >= 9;
      yield finding(
        ctx,
        component: app.package,
        componentLabel: app.label,
        title: LText('Possible monitoring app: ${app.label}', 'Possible app de surveillance : ${app.label}'),
        description: const LText(
          'This app combines several capabilities used by stalkerware to monitor someone covertly. It may still be legitimate (e.g. parental control you installed). If you did not install it, read the safety advice before removing it: removal can alert the person who installed it.',
          'Cette app combine plusieurs capacités utilisées par les stalkerwares pour surveiller quelqu’un à son insu. Elle peut être légitime (ex. contrôle parental installé par vous). Si vous ne l’avez pas installée, lisez les conseils de sécurité avant de la supprimer : la suppression peut alerter la personne qui l’a installée.',
        ),
        severity: high ? Severity.high : Severity.medium,
        confidence: high ? Confidence.medium : Confidence.low,
        classification: Classification.suspicious,
        category: FindingCategory.stalkerware,
        method: const LText(
          'Local heuristic: capability correlation (score in evidence)',
          'Heuristique locale : corrélation de capacités (score dans les preuves)',
        ),
        limitations: const LText(
          'Behaviour is inferred from declared capabilities, not observed activity.',
          'Le comportement est déduit des capacités déclarées, pas d’une activité observée.',
        ),
        evidence: {'score': '$total', ...signals.map((k, v) => MapEntry(k, '+$v')), 'installer': app.installer ?? 'unknown'},
        remediation: [
          Steps.advice(
            'If you might be in danger, plan with a trusted person or support service before removing it (e.g. stopstalkerware.org).',
            'Si vous êtes peut-être en danger, préparez-vous avec une personne de confiance ou une association avant de la supprimer (ex. stopstalkerware.org).',
          ),
          Steps.appDetails(app.package),
          Steps.uninstall(app.package),
          Steps.passwordsFromTrustedDevice,
        ],
      );
    }
  }
}

class SideloadedSensitiveRule extends DetectionRule {
  const SideloadedSensitiveRule();
  @override
  String get id => 'AND-APP-002';
  @override
  LText get name => const LText('Side-loaded apps with sensitive access', 'Apps hors store avec accès sensibles');
  @override
  LText get description => const LText(
    'Apps installed outside app stores that hold SMS, call-log or microphone permissions.',
    'Apps installées hors store qui détiennent SMS, journal d’appels ou micro.',
  );
  @override
  Set<DevicePlatform> get platforms => _android;
  @override
  Set<Capability> get requires => const {Capability.appInventory};
  @override
  LText get confidenceModel => const LText('Low: side-loading alone is common for legitimate apps.', 'Faible : l’installation hors store est courante.');
  @override
  LText get knownFalsePositives => const LText('Apps from GitHub/F-Droid, beta builds, enterprise apps.', 'Apps GitHub/F-Droid, bêtas, apps d’entreprise.');
  @override
  bool available(RuleContext ctx) => ctx.snapshot.appInventorySupported;

  static const _high = {
    'android.permission.READ_SMS',
    'android.permission.RECEIVE_SMS',
    'android.permission.READ_CALL_LOG',
    permRecordAudio,
    permBackgroundLocation,
  };

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    for (final app in ctx.snapshot.apps) {
      if (!app.isSideloaded) continue;
      final hits = app.grantedPermissions.intersection(_high);
      if (hits.isEmpty) continue;
      yield finding(
        ctx,
        component: app.package,
        componentLabel: app.label,
        title: LText('Side-loaded app with sensitive access: ${app.label}', 'App hors store avec accès sensibles : ${app.label}'),
        description: const LText(
          'Apps from outside an app store skip store malware review. This one holds permissions that expose private communications.',
          'Les apps hors store échappent à l’analyse du store. Celle-ci détient des autorisations qui exposent vos communications.',
        ),
        severity: Severity.low,
        confidence: Confidence.low,
        classification: Classification.unverified,
        category: FindingCategory.permissions,
        method: const LText('PackageManager install source + granted permissions', 'Source d’installation + autorisations accordées'),
        limitations: const LText('Install source is not reported for every app.', 'La source n’est pas rapportée pour toutes les apps.'),
        evidence: {'installer': app.installer ?? 'unknown', 'granted': hits.map((p) => p.split('.').last).join(', ')},
        remediation: [Steps.appDetails(app.package)],
      );
    }
  }
}

class DebuggableAppRule extends DetectionRule {
  const DebuggableAppRule();
  @override
  String get id => 'AND-APP-003';
  @override
  LText get name => const LText('Debuggable apps', 'Apps débogables');
  @override
  LText get description => const LText('Release apps should never be debuggable.', 'Une app publiée ne devrait jamais être débogable.');
  @override
  Set<DevicePlatform> get platforms => _android;
  @override
  Set<Capability> get requires => const {Capability.appInventory};
  @override
  LText get confidenceModel => const LText('High: ApplicationInfo.FLAG_DEBUGGABLE.', 'Élevée : FLAG_DEBUGGABLE.');
  @override
  LText get knownFalsePositives => const LText('Apps you are developing.', 'Apps que vous développez.');
  @override
  bool available(RuleContext ctx) => ctx.snapshot.appInventorySupported;

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    for (final app in ctx.snapshot.apps.where((a) => a.debuggable && !a.isSystem)) {
      yield finding(
        ctx,
        component: app.package,
        componentLabel: app.label,
        title: LText('Debuggable app: ${app.label}', 'App débogable : ${app.label}'),
        description: const LText(
          'Its data can be extracted over USB debugging; it is likely a development or repackaged build.',
          'Ses données peuvent être extraites via le débogage USB ; probablement une build de développement ou reconditionnée.',
        ),
        severity: Severity.low,
        confidence: Confidence.high,
        classification: Classification.exposure,
        category: FindingCategory.permissions,
        method: const LText('ApplicationInfo flags', 'Drapeaux ApplicationInfo'),
        limitations: const LText('None.', 'Aucune.'),
        evidence: {'installer': app.installer ?? 'unknown'},
        remediation: [Steps.appDetails(app.package)],
      );
    }
  }
}

class InstallSourcesRule extends DetectionRule {
  const InstallSourcesRule();
  @override
  String get id => 'AND-APP-004';
  @override
  LText get name => const LText('Apps allowed to install other apps', 'Apps autorisées à installer des apps');
  @override
  LText get description => const LText(
    '"Install unknown apps" lets an app drop further apps on the device.',
    '« Installer des apps inconnues » permet à une app d’en installer d’autres.',
  );
  @override
  Set<DevicePlatform> get platforms => _android;
  @override
  Set<Capability> get requires => const {Capability.appInventory};
  @override
  LText get confidenceModel => const LText('High when the app-op is readable; unknown values are skipped.', 'Élevée si l’app-op est lisible.');
  @override
  LText get knownFalsePositives =>
      const LText('Browsers and file managers you used to install an APK.', 'Navigateurs et gestionnaires de fichiers utilisés pour installer un APK.');
  @override
  bool available(RuleContext ctx) => ctx.snapshot.appInventorySupported;

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    for (final app in ctx.snapshot.apps.where((a) => !a.isSystem && a.appOps['installPackages'] == 'allowed')) {
      yield finding(
        ctx,
        component: app.package,
        componentLabel: app.label,
        title: LText('Can install apps: ${app.label}', 'Peut installer des apps : ${app.label}'),
        description: description,
        severity: Severity.low,
        confidence: Confidence.high,
        classification: Classification.exposure,
        category: FindingCategory.permissions,
        method: const LText('AppOpsManager REQUEST_INSTALL_PACKAGES', 'AppOpsManager REQUEST_INSTALL_PACKAGES'),
        limitations: const LText('None.', 'Aucune.'),
        evidence: {'appOp': 'allowed'},
        remediation: [
          Steps.settings('unknownSources', 'Revoke "Install unknown apps" when not needed', 'Révoquer « Installer des apps inconnues » si inutile'),
        ],
      );
    }
  }
}

class IndicatorMatchRule extends DetectionRule {
  const IndicatorMatchRule();
  @override
  String get id => 'AND-IOC-001';
  @override
  LText get name => const LText('Known malware / stalkerware indicators', 'Indicateurs connus de malware / stalkerware');
  @override
  LText get description => const LText(
    'Matches package names and signing certificates against the signed rule pack.',
    'Compare noms de paquets et certificats de signature au pack de règles signé.',
  );
  @override
  Set<DevicePlatform> get platforms => _android;
  @override
  Set<Capability> get requires => const {Capability.appInventory};
  @override
  LText get confidenceModel => const LText(
    'Signing-certificate match → confirmed (high). Package-name match only → suspicious (medium), since names can be reused.',
    'Certificat → confirmé (élevée). Nom de paquet seul → suspect (moyenne), un nom pouvant être réutilisé.',
  );
  @override
  LText get knownFalsePositives => const LText('Package names reused by unrelated apps.', 'Noms de paquets réutilisés par d’autres apps.');
  @override
  bool available(RuleContext ctx) => ctx.snapshot.appInventorySupported;

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    for (final app in ctx.snapshot.apps) {
      final certHit = app.signingSha256.map((c) => ctx.pack.lookup('cert_sha256', c)).nonNulls.firstOrNull;
      final pkgHit = ctx.pack.lookup('package', app.package);
      final hit = certHit ?? pkgHit;
      if (hit == null) continue;
      final confirmed = certHit != null;
      yield finding(
        ctx,
        component: app.package,
        componentLabel: app.label,
        title: LText('${hit.test ? '[TEST] ' : ''}${hit.family} detected: ${app.label}', '${hit.test ? '[TEST] ' : ''}${hit.family} détecté : ${app.label}'),
        description: LText(
          'This app matches a known ${hit.category} indicator from ${hit.source}.',
          'Cette app correspond à un indicateur ${hit.category} connu de ${hit.source}.',
        ),
        severity: hit.category == 'adware' || hit.category == 'pua' ? Severity.medium : Severity.critical,
        confidence: confirmed ? Confidence.high : Confidence.medium,
        classification: confirmed ? Classification.confirmedMalicious : Classification.suspicious,
        category: hit.category == 'stalkerware' ? FindingCategory.stalkerware : FindingCategory.malware,
        method: LText(
          'Indicator match (${confirmed ? 'signing certificate' : 'package name'}) — rule pack v${ctx.pack.version}',
          'Correspondance d’indicateur (${confirmed ? 'certificat de signature' : 'nom de paquet'}) — pack v${ctx.pack.version}',
        ),
        limitations: const LText('Only indicators present in the rule pack are recognised.', 'Seuls les indicateurs du pack sont reconnus.'),
        evidence: {
          'indicatorType': hit.type,
          'indicator': hit.value,
          'family': hit.family,
          'source': hit.source,
          if (hit.license != null) 'license': hit.license!,
        },
        remediation: [
          if (hit.category == 'stalkerware')
            Steps.advice(
              'Removing stalkerware may alert the person who installed it. If you feel unsafe, contact a support service first.',
              'Supprimer un stalkerware peut alerter la personne qui l’a installé. Si vous vous sentez en danger, contactez d’abord une association.',
            ),
          Steps.uninstall(app.package),
          Steps.passwordsFromTrustedDevice,
        ],
      );
    }
  }
}

class MicrophoneAppsRule extends DetectionRule {
  const MicrophoneAppsRule();
  @override
  String get id => 'AND-MIC-001';
  @override
  LText get name => const LText('Apps allowed to use the microphone', 'Apps autorisées à utiliser le micro');
  @override
  LText get description =>
      const LText('Summarises third-party apps that currently hold the microphone permission.', 'Résume les apps tierces qui détiennent l’autorisation micro.');
  @override
  Set<DevicePlatform> get platforms => _android;
  @override
  Set<Capability> get requires => const {Capability.appInventory};
  @override
  LText get confidenceModel =>
      const LText('High that the permission is granted; says nothing about actual use.', 'Élevée sur l’autorisation ; ne dit rien de l’usage réel.');
  @override
  LText get knownFalsePositives => const LText('Messaging, voice assistant and recorder apps.', 'Messageries, assistants vocaux, dictaphones.');
  @override
  bool available(RuleContext ctx) => ctx.snapshot.appInventorySupported;

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    final apps = ctx.snapshot.apps.where((a) => !a.isSystem && a.granted(permRecordAudio)).toList();
    if (apps.isEmpty) return;
    final risky = apps.where((a) => a.isSideloaded || !a.hasLauncher).toList();
    yield finding(
      ctx,
      component: 'microphone',
      title: LText('${apps.length} app(s) can use the microphone', '${apps.length} app(s) peuvent utiliser le micro'),
      description: const LText(
        'Permission granted does not mean the microphone is being used. Android shows a green indicator when an app records, and the Privacy Dashboard lists the last 24 hours (7 days on recent versions) of access.',
        'Autorisation accordée ne veut pas dire micro utilisé. Android affiche un indicateur vert lors d’un enregistrement et le tableau de bord de confidentialité liste les accès des dernières 24 h (7 jours sur les versions récentes).',
      ),
      severity: risky.isEmpty ? Severity.informational : Severity.low,
      confidence: Confidence.high,
      classification: risky.isEmpty ? Classification.informational : Classification.unverified,
      category: FindingCategory.microphone,
      method: const LText('PackageInfo.requestedPermissionsFlags (GRANTED)', 'PackageInfo.requestedPermissionsFlags (GRANTED)'),
      limitations: const LText(
        'Android does not let third-party apps see other apps’ microphone usage history.',
        'Android ne permet pas aux apps tierces de voir l’historique micro des autres apps.',
      ),
      evidence: {'apps': apps.map((a) => a.label).take(30).join(', '), if (risky.isNotEmpty) 'sideloadedOrHidden': risky.map((a) => a.label).join(', ')},
      remediation: [
        Steps.settings('privacyDashboard', 'Open Privacy Dashboard to see recent microphone access', 'Ouvrir le tableau de bord de confidentialité'),
      ],
    );
  }
}

class BackgroundLocationRule extends DetectionRule {
  const BackgroundLocationRule();
  @override
  String get id => 'AND-LOC-001';
  @override
  LText get name => const LText('Background location', 'Localisation en arrière-plan');
  @override
  LText get description => const LText('Apps allowed to access location all the time.', 'Apps autorisées à accéder à la localisation en permanence.');
  @override
  Set<DevicePlatform> get platforms => _android;
  @override
  Set<Capability> get requires => const {Capability.appInventory};
  @override
  LText get confidenceModel => const LText('High that the permission is granted.', 'Élevée sur l’autorisation.');
  @override
  LText get knownFalsePositives => const LText('Navigation, fitness, family-sharing and weather widgets.', 'Navigation, sport, partage familial, météo.');
  @override
  bool available(RuleContext ctx) => ctx.snapshot.appInventorySupported;

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    for (final app in ctx.snapshot.apps.where((a) => !a.isSystem && a.granted(permBackgroundLocation))) {
      final precise = app.granted(permFineLocation);
      final risky = app.isSideloaded || !app.hasLauncher;
      yield finding(
        ctx,
        component: app.package,
        componentLabel: app.label,
        title: LText('Location “all the time”: ${app.label}', 'Localisation « toujours » : ${app.label}'),
        description: LText(
          'This app can read your ${precise ? 'precise' : 'approximate'} location even when closed, enough to reconstruct your daily movements.',
          'Cette app peut lire votre localisation ${precise ? 'précise' : 'approximative'} même fermée, assez pour reconstituer vos déplacements.',
        ),
        severity: risky ? Severity.medium : Severity.low,
        confidence: Confidence.high,
        classification: risky ? Classification.unverified : Classification.exposure,
        category: FindingCategory.tracking,
        method: const LText('Granted ACCESS_BACKGROUND_LOCATION', 'ACCESS_BACKGROUND_LOCATION accordée'),
        limitations: const LText('Cannot see when location was actually accessed.', 'Impossible de voir quand la localisation a été lue.'),
        evidence: {'precise': '$precise', 'installer': app.installer ?? 'unknown'},
        remediation: [Steps.appDetails(app.package)],
      );
    }
  }
}

final androidRules = <DetectionRule>[
  const ScreenLockRule(),
  const EncryptionRule(),
  const AdbRule(),
  const DeveloperOptionsRule(),
  const PatchLevelRule(),
  const OsVersionRule(),
  const RootRule(),
  const BootStateRule(),
  const EmulatorRule(),
  const AccessibilityRule(),
  const DeviceAdminRule(),
  const NotificationListenerRule(),
  const KeyboardRule(),
  const UserCaRule(),
  const StalkerwareCorrelationRule(),
  const SideloadedSensitiveRule(),
  const DebuggableAppRule(),
  const InstallSourcesRule(),
  const IndicatorMatchRule(),
  const MicrophoneAppsRule(),
  const BackgroundLocationRule(),
];

/// Convenience used by the app-risk screen.
int appRiskScore(AppInfo app) {
  var s = 0;
  if (app.isSideloaded) s += 2;
  if (!app.hasLauncher && !app.isSystem) s += 2;
  final groups = <String>{};
  for (final p in app.grantedPermissions) {
    final sp = sensitiveByName[p];
    if (sp != null && groups.add(sp.group)) s += sp.weight;
  }
  if (app.isAccessibilityProvider) s += 1;
  if (app.isDeviceAdminProvider) s += 1;
  return s;
}
