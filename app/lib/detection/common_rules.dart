import '../core/models.dart';
import 'rule.dart';

const _both = {DevicePlatform.android, DevicePlatform.ios};
const _ios = {DevicePlatform.ios};

const _netMethod = LText('Active network properties reported by the OS', 'Propriétés du réseau actif rapportées par l’OS');

// ------------------------------------------------------------------ network (both platforms)

class ProxyRule extends DetectionRule {
  const ProxyRule();
  @override
  String get id => 'NET-001';
  @override
  LText get name => const LText('HTTP proxy', 'Proxy HTTP');
  @override
  LText get description => const LText('A configured proxy can see or alter web traffic.', 'Un proxy configuré peut voir ou modifier le trafic web.');
  @override
  Set<DevicePlatform> get platforms => _both;
  @override
  LText get confidenceModel => const LText('High that a proxy is configured.', 'Élevée sur la présence du proxy.');
  @override
  LText get knownFalsePositives => const LText('Corporate networks, debugging tools.', 'Réseaux d’entreprise, outils de débogage.');

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    final proxy = (ctx.snapshot.network['proxy'] ?? ctx.snapshot.device['proxy']) as Map?;
    if (proxy == null || (proxy['host'] == null && proxy['pacUrl'] == null)) return;
    yield finding(
      ctx,
      component: 'proxy',
      title: const LText('A network proxy is configured', 'Un proxy réseau est configuré'),
      description: const LText(
        'Unencrypted traffic passes through this proxy; with a trusted CA certificate it could also inspect HTTPS.',
        'Le trafic non chiffré passe par ce proxy ; avec un certificat CA de confiance, il pourrait aussi inspecter le HTTPS.',
      ),
      severity: Severity.medium,
      confidence: Confidence.high,
      classification: Classification.unverified,
      category: FindingCategory.network,
      method: _netMethod,
      limitations: const LText('Cannot tell whether traffic is being logged.', 'Impossible de savoir si le trafic est journalisé.'),
      evidence: {'host': '${proxy['host']}', 'port': '${proxy['port']}', if (proxy['pacUrl'] != null) 'pac': '${proxy['pacUrl']}'},
      remediation: [Steps.settings('wifi', 'Check the Wi-Fi network’s proxy settings', 'Vérifier les réglages proxy du Wi-Fi')],
    );
  }
}

class VpnRule extends DetectionRule {
  const VpnRule();
  @override
  String get id => 'NET-002';
  @override
  LText get name => const LText('Active VPN', 'VPN actif');
  @override
  LText get description => const LText('A VPN routes all traffic through its operator.', 'Un VPN fait passer tout le trafic par son opérateur.');
  @override
  Set<DevicePlatform> get platforms => _both;
  @override
  LText get confidenceModel =>
      const LText('High that a VPN is active; the app cannot identify which one on iOS.', 'Élevée sur l’activation ; impossible d’identifier lequel sur iOS.');
  @override
  LText get knownFalsePositives =>
      const LText('Your own VPN, corporate VPN, private relay, ad blockers using local VPN.', 'Votre VPN, VPN d’entreprise, ad-blockers en VPN local.');

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    final active = ctx.snapshot.network['vpnActive'] == true || ctx.snapshot.device['vpnActive'] == true;
    if (!active) return;
    final providers = ctx.snapshot.apps.where((a) => a.isVpnProvider && !a.isSystem).map((a) => a.label).toList();
    yield finding(
      ctx,
      component: 'vpn',
      title: const LText('A VPN is active', 'Un VPN est actif'),
      description: const LText(
        'Make sure you recognise and trust this VPN: its operator can see your traffic metadata and any unencrypted content.',
        'Vérifiez que vous reconnaissez ce VPN : son opérateur voit les métadonnées et tout contenu non chiffré.',
      ),
      severity: Severity.informational,
      confidence: Confidence.high,
      classification: Classification.unverified,
      category: FindingCategory.network,
      method: _netMethod,
      limitations: const LText(
        'VPN apps are listed when app inventory is available (Android only).',
        'Les apps VPN sont listées si l’inventaire est disponible (Android).',
      ),
      evidence: {if (providers.isNotEmpty) 'vpnCapableApps': providers.join(', ')},
      remediation: [
        ctx.platform == DevicePlatform.ios
            ? Steps.advice('Review Settings → General → VPN & Device Management.', 'Vérifier Réglages → Général → VPN et gestion de l’appareil.')
            : Steps.settings('vpn', 'Review VPN settings', 'Vérifier les réglages VPN'),
      ],
    );
  }
}

class WifiSecurityRule extends DetectionRule {
  const WifiSecurityRule();
  @override
  String get id => 'NET-003';
  @override
  LText get name => const LText('Wi-Fi encryption', 'Chiffrement Wi-Fi');
  @override
  LText get description => const LText('Detects open and WEP Wi-Fi networks.', 'Détecte les réseaux Wi-Fi ouverts et WEP.');
  @override
  Set<DevicePlatform> get platforms => _both;
  @override
  LText get confidenceModel =>
      const LText('High on Android 12+; unavailable on iOS and older Android.', 'Élevée sur Android 12+ ; indisponible sur iOS et anciens Android.');
  @override
  LText get knownFalsePositives =>
      const LText('OWE ("Enhanced Open") is encrypted and not flagged.', 'OWE (« Enhanced Open ») est chiffré et n’est pas signalé.');
  @override
  bool available(RuleContext ctx) => ctx.snapshot.network['transport'] != 'wifi' || ctx.snapshot.network['wifiSecurity'] != null;

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    if (ctx.snapshot.network['transport'] != 'wifi') return;
    final sec = ctx.snapshot.network['wifiSecurity'] as String?;
    if (sec != 'open' && sec != 'wep') return;
    yield finding(
      ctx,
      component: 'wifi',
      title: sec == 'open'
          ? const LText('Connected to an open Wi-Fi network', 'Connecté à un Wi-Fi ouvert')
          : const LText('Connected to a WEP Wi-Fi network', 'Connecté à un Wi-Fi WEP'),
      description: const LText(
        'Others nearby can observe unencrypted traffic and impersonate this network.',
        'Des personnes à proximité peuvent observer le trafic non chiffré et usurper ce réseau.',
      ),
      severity: sec == 'wep' ? Severity.high : Severity.medium,
      confidence: Confidence.high,
      classification: Classification.exposure,
      category: FindingCategory.network,
      method: const LText('WifiInfo.getCurrentSecurityType', 'WifiInfo.getCurrentSecurityType'),
      limitations: const LText('Does not detect evil-twin access points with a password.', 'Ne détecte pas les faux points d’accès protégés par mot de passe.'),
      evidence: {'security': sec!},
      remediation: [
        Steps.advice(
          'Avoid logging in to accounts on this network, or use a trusted VPN.',
          'Évitez de vous connecter à vos comptes sur ce réseau ou utilisez un VPN de confiance.',
        ),
        Steps.settings('wifi', 'Open Wi-Fi settings', 'Ouvrir les réglages Wi-Fi'),
      ],
    );
  }
}

class NetworkValidationRule extends DetectionRule {
  const NetworkValidationRule();
  @override
  String get id => 'NET-004';
  @override
  LText get name => const LText('Captive portal / unvalidated network', 'Portail captif / réseau non validé');
  @override
  LText get description => const LText('The OS could not validate Internet access on this network.', 'L’OS n’a pas pu valider l’accès Internet sur ce réseau.');
  @override
  Set<DevicePlatform> get platforms => const {DevicePlatform.android};
  @override
  LText get confidenceModel => const LText('High: NetworkCapabilities flags.', 'Élevée : drapeaux NetworkCapabilities.');
  @override
  LText get knownFalsePositives => const LText('Hotel and airport login pages.', 'Pages de connexion d’hôtels et d’aéroports.');

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    final n = ctx.snapshot.network;
    if (n['connected'] != true) return;
    if (n['captivePortal'] == true || n['validated'] == false) {
      yield finding(
        ctx,
        component: 'validation',
        title: const LText('Network requires sign-in or is not validated', 'Le réseau exige une connexion ou n’est pas validé'),
        description: const LText(
          'Be careful entering credentials on captive portal pages; they are a common phishing vector.',
          'Prudence avant de saisir des identifiants sur un portail captif ; c’est un vecteur d’hameçonnage courant.',
        ),
        severity: Severity.low,
        confidence: Confidence.high,
        classification: Classification.exposure,
        category: FindingCategory.network,
        method: _netMethod,
        limitations: const LText('None.', 'Aucune.'),
        evidence: {'captivePortal': '${n['captivePortal']}', 'validated': '${n['validated']}'},
      );
    }
  }
}

class PrivateDnsRule extends DetectionRule {
  const PrivateDnsRule();
  @override
  String get id => 'NET-005';
  @override
  LText get name => const LText('Private DNS', 'DNS privé');
  @override
  LText get description =>
      const LText('Encrypted DNS hides the sites you visit from the local network.', 'Le DNS chiffré masque les sites visités au réseau local.');
  @override
  Set<DevicePlatform> get platforms => const {DevicePlatform.android};
  @override
  LText get confidenceModel => const LText('High: LinkProperties.isPrivateDnsActive (Android 9+).', 'Élevée : LinkProperties.isPrivateDnsActive (Android 9+).');
  @override
  LText get knownFalsePositives => const LText('Networks that block DoT.', 'Réseaux bloquant DoT.');
  @override
  bool available(RuleContext ctx) => ctx.snapshot.network['privateDnsActive'] != null;

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    if (ctx.snapshot.network['privateDnsActive'] == false && ctx.snapshot.network['connected'] == true) {
      yield finding(
        ctx,
        component: 'dns',
        title: const LText('Private DNS is not active', 'Le DNS privé n’est pas actif'),
        description: description,
        severity: Severity.informational,
        confidence: Confidence.high,
        classification: Classification.informational,
        category: FindingCategory.network,
        method: _netMethod,
        limitations: const LText('A VPN may provide its own encrypted DNS.', 'Un VPN peut fournir son propre DNS chiffré.'),
        evidence: {'dnsServers': '${ctx.snapshot.network['dnsServers']}'},
        remediation: [
          Steps.advice(
            'Settings → Network → Private DNS → Automatic or a trusted provider.',
            'Paramètres → Réseau → DNS privé → Automatique ou un fournisseur de confiance.',
          ),
        ],
      );
    }
  }
}

// ------------------------------------------------------------------ iOS

class IosPasscodeRule extends DetectionRule {
  const IosPasscodeRule();
  @override
  String get id => 'IOS-CFG-001';
  @override
  LText get name => const LText('Passcode', 'Code d’accès');
  @override
  LText get description => const LText('Detects devices without a passcode.', 'Détecte un appareil sans code.');
  @override
  Set<DevicePlatform> get platforms => _ios;
  @override
  LText get confidenceModel => const LText('High: LAContext deviceOwnerAuthentication.', 'Élevée : LAContext deviceOwnerAuthentication.');
  @override
  LText get knownFalsePositives => const LText('None known.', 'Aucun connu.');

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    if (ctx.snapshot.d<bool>('deviceSecure') == false && ctx.snapshot.d<bool>('isSimulator') != true) {
      yield finding(
        ctx,
        title: const LText('No passcode set', 'Aucun code défini'),
        description: const LText(
          'Without a passcode, iOS data protection is weak and anyone with the phone can access your data.',
          'Sans code, la protection des données iOS est faible et toute personne ayant le téléphone accède à vos données.',
        ),
        severity: Severity.high,
        confidence: Confidence.high,
        classification: Classification.exposure,
        category: FindingCategory.configuration,
        method: const LText('LocalAuthentication framework', 'Framework LocalAuthentication'),
        limitations: const LText('Passcode strength is not visible.', 'La robustesse du code n’est pas visible.'),
        evidence: {'canEvaluatePolicy': 'false'},
        remediation: [Steps.advice('Settings → Face ID/Touch ID & Passcode → Turn Passcode On.', 'Réglages → Face ID/Touch ID et code → Activer le code.')],
      );
    }
  }
}

class IosVersionRule extends DetectionRule {
  const IosVersionRule();
  @override
  String get id => 'IOS-CFG-002';
  @override
  LText get name => const LText('iOS version', 'Version d’iOS');
  @override
  LText get description => const LText(
    'Compares the iOS major version with the latest major listed in the rule pack.',
    'Compare la version majeure d’iOS à la dernière indiquée dans le pack.',
  );
  @override
  Set<DevicePlatform> get platforms => _ios;
  @override
  LText get confidenceModel => const LText('High; accuracy depends on rule-pack freshness.', 'Élevée ; dépend de la fraîcheur du pack.');
  @override
  LText get knownFalsePositives => const LText('Outdated rule pack.', 'Pack de règles obsolète.');

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    final v = ctx.snapshot.d<String>('osVersion');
    final major = int.tryParse(v?.split('.').first ?? '');
    final latest = ctx.pack.cfgInt('iosLatestMajor', 0);
    if (major == null || latest == 0 || major >= latest - 1) return;
    yield finding(
      ctx,
      title: LText('iOS $v is outdated', 'iOS $v est obsolète'),
      description: const LText(
        'Older iOS versions miss fixes for vulnerabilities exploited by mercenary spyware.',
        'Les anciennes versions d’iOS n’ont pas les correctifs contre des failles exploitées par des logiciels espions.',
      ),
      severity: Severity.high,
      confidence: Confidence.high,
      classification: Classification.exposure,
      category: FindingCategory.configuration,
      method: const LText('UIDevice.systemVersion vs rule pack', 'UIDevice.systemVersion vs pack de règles'),
      limitations: const LText('Minor updates are not compared.', 'Les mises à jour mineures ne sont pas comparées.'),
      evidence: {'osVersion': '$v', 'latestMajor': '$latest'},
      remediation: [Steps.advice('Settings → General → Software Update.', 'Réglages → Général → Mise à jour logicielle.')],
    );
  }
}

class JailbreakRule extends DetectionRule {
  const JailbreakRule();
  @override
  String get id => 'IOS-INT-001';
  @override
  LText get name => const LText('Jailbreak indicators', 'Indicateurs de jailbreak');
  @override
  LText get description => const LText(
    'Looks for jailbreak files, URL schemes, injected libraries and sandbox escape.',
    'Recherche fichiers, schémas d’URL, bibliothèques injectées et sortie de sandbox.',
  );
  @override
  Set<DevicePlatform> get platforms => _ios;
  @override
  LText get confidenceModel => const LText(
    'Medium; injected dylibs or writable system paths raise it. Absence proves nothing.',
    'Moyenne ; bibliothèques injectées ou chemins système inscriptibles l’augmentent. L’absence ne prouve rien.',
  );
  @override
  LText get knownFalsePositives => const LText('Rare: apps that register the same URL schemes.', 'Rare : apps utilisant les mêmes schémas d’URL.');

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    final jb = (ctx.snapshot.device['jailbreak'] as Map?) ?? const {};
    final paths = (jb['paths'] as List?) ?? const [];
    final schemes = (jb['schemes'] as List?) ?? const [];
    final dylibs = (jb['dylibs'] as List?) ?? const [];
    final writable = jb['sandboxWritable'] == true;
    if (paths.isEmpty && schemes.isEmpty && dylibs.isEmpty && !writable) return;
    final strong = dylibs.isNotEmpty || writable || paths.length >= 2;
    yield finding(
      ctx,
      title: const LText('Jailbreak indicators found', 'Indicateurs de jailbreak détectés'),
      description: const LText(
        'A jailbreak disables iOS code signing and sandboxing, letting any installed tweak access other apps’ data. It does not by itself mean the device is infected.',
        'Un jailbreak désactive la signature et la sandbox d’iOS : un tweak peut accéder aux données des autres apps. Cela ne signifie pas à lui seul une infection.',
      ),
      severity: Severity.high,
      confidence: strong ? Confidence.medium : Confidence.low,
      classification: Classification.exposure,
      category: FindingCategory.integrity,
      method: const LText('File, URL-scheme, dyld image and sandbox-write probes', 'Sondes fichiers, schémas d’URL, images dyld et écriture sandbox'),
      limitations: const LText(
        'Jailbreaks can hide from apps; detection is inherently incomplete.',
        'Un jailbreak peut se cacher ; la détection est forcément incomplète.',
      ),
      evidence: {
        if (paths.isNotEmpty) 'paths': paths.join(', '),
        if (schemes.isNotEmpty) 'schemes': schemes.join(', '),
        if (dylibs.isNotEmpty) 'dylibs': dylibs.take(5).join(', '),
        'sandboxWritable': '$writable',
      },
      remediation: [
        Steps.advice(
          'If you did not jailbreak this device, update or restore iOS from a computer (this removes the jailbreak).',
          'Si vous n’avez pas jailbreaké l’appareil, mettez à jour ou restaurez iOS depuis un ordinateur.',
        ),
        Steps.passwordsFromTrustedDevice,
      ],
    );
  }
}

class DebuggerRule extends DetectionRule {
  const DebuggerRule();
  @override
  String get id => 'IOS-INT-002';
  @override
  LText get name => const LText('Debugger attached', 'Débogueur attaché');
  @override
  LText get description => const LText('Detects that this app is being debugged or instrumented.', 'Détecte que cette app est déboguée ou instrumentée.');
  @override
  Set<DevicePlatform> get platforms => _ios;
  @override
  LText get confidenceModel => const LText('High: sysctl P_TRACED.', 'Élevée : sysctl P_TRACED.');
  @override
  LText get knownFalsePositives => const LText('Running from Xcode.', 'Exécution depuis Xcode.');

  @override
  Iterable<Finding> evaluate(RuleContext ctx) sync* {
    if (ctx.snapshot.d<bool>('debuggerAttached') == true) {
      yield finding(
        ctx,
        title: const LText('Sentinel is running under a debugger', 'Sentinel s’exécute sous un débogueur'),
        description: const LText('Results may be manipulated while a debugger is attached.', 'Les résultats peuvent être manipulés sous débogueur.'),
        severity: Severity.low,
        confidence: Confidence.high,
        classification: Classification.informational,
        category: FindingCategory.integrity,
        method: const LText('sysctl KERN_PROC', 'sysctl KERN_PROC'),
        limitations: const LText('None.', 'Aucune.'),
        evidence: {'P_TRACED': 'true'},
      );
    }
  }
}

final commonRules = <DetectionRule>[
  const ProxyRule(),
  const VpnRule(),
  const WifiSecurityRule(),
  const NetworkValidationRule(),
  const PrivateDnsRule(),
  const IosPasscodeRule(),
  const IosVersionRule(),
  const JailbreakRule(),
  const DebuggerRule(),
];
