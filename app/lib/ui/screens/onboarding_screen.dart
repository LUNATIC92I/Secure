import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../core/models.dart';
import '../../state/app_state.dart';
import '../l10n.dart';
import '../theme.dart';
import '../widgets/common.dart';

/// Capability matrix entry shown during onboarding and in Help.
class PlatformCapability {
  const PlatformCapability(this.label, this.android, this.ios);
  final LText label;

  /// yes | partial | no
  final String android;
  final String ios;
}

const capabilities = <PlatformCapability>[
  PlatformCapability(LText('Installed-app inventory & permission review', 'Inventaire des apps et revue des autorisations'), 'yes', 'no'),
  PlatformCapability(LText('Stalkerware / malware indicator matching', 'Indicateurs stalkerware / malware'), 'yes', 'no'),
  PlatformCapability(LText('Accessibility, device-admin, notification-access review', 'Revue accessibilité, administrateurs, accès notifications'), 'yes', 'no'),
  PlatformCapability(LText('APK file static analysis', 'Analyse statique de fichiers APK'), 'yes', 'no'),
  PlatformCapability(LText('Screen lock / passcode', 'Verrouillage / code'), 'yes', 'yes'),
  PlatformCapability(LText('OS version & security patch', 'Version OS et correctif'), 'yes', 'partial'),
  PlatformCapability(LText('Root / jailbreak indicators (incomplete by nature)', 'Indicateurs root / jailbreak (forcément incomplets)'), 'partial', 'partial'),
  PlatformCapability(LText('VPN & proxy detection', 'Détection VPN et proxy'), 'yes', 'yes'),
  PlatformCapability(LText('User-installed CA certificates', 'Certificats CA utilisateur'), 'yes', 'no'),
  PlatformCapability(LText('Wi-Fi encryption type', 'Type de chiffrement Wi-Fi'), 'partial', 'no'),
  PlatformCapability(LText('Phishing link analysis', 'Analyse de liens d’hameçonnage'), 'yes', 'yes'),
  PlatformCapability(LText('Bluetooth tracker scan', 'Recherche de traceurs Bluetooth'), 'partial', 'partial'),
  PlatformCapability(LText('Other apps’ live microphone use', 'Usage du micro par les autres apps'), 'no', 'no'),
  PlatformCapability(LText('Call interception / IMSI-catcher detection', 'Interception d’appels / IMSI-catcher'), 'no', 'no'),
  PlatformCapability(LText('Configuration profiles / MDM listing', 'Liste des profils / MDM'), 'partial', 'no'),
  PlatformCapability(LText('Daily background assessment (OS-scheduled)', 'Évaluation quotidienne (planifiée par l’OS)'), 'yes', 'partial'),
];

class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({super.key});
  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<OnboardingScreen> {
  final _page = PageController();
  int _index = 0;

  @override
  Widget build(BuildContext context) {
    final state = context.read<AppState>();
    final pages = [_welcome(context), CapabilityMatrix(platform: state.platform), _privacy(context)];
    return Scaffold(
      body: SafeArea(
        child: Responsive(
          child: Column(children: [
            Expanded(child: PageView(controller: _page, onPageChanged: (i) => setState(() => _index = i), children: pages)),
            Padding(
              padding: const EdgeInsets.all(16),
              child: Row(children: [
                for (var i = 0; i < pages.length; i++)
                  Container(
                    margin: const EdgeInsets.only(right: 6),
                    width: i == _index ? 22 : 8,
                    height: 8,
                    decoration: BoxDecoration(color: i == _index ? SocColors.blue : SocColors.line, borderRadius: BorderRadius.circular(8)),
                  ),
                const Spacer(),
                FilledButton(
                  onPressed: () async {
                    if (_index < pages.length - 1) {
                      await _page.nextPage(duration: const Duration(milliseconds: 300), curve: Curves.easeOut);
                    } else {
                      await state.updateSettings((s) => s.onboarded = true);
                    }
                  },
                  child: Text(_index < pages.length - 1 ? context.tr('Next', 'Suivant') : context.tr('Start', 'Commencer')),
                ),
              ]),
            ),
          ]),
        ),
      ),
    );
  }

  Widget _welcome(BuildContext context) => ListView(padding: const EdgeInsets.all(24), children: [
        const SizedBox(height: 24),
        const Center(child: ScanRadar(size: 140)),
        const SizedBox(height: 24),
        Text(context.tr('Your personal Mobile SOC', 'Votre SOC mobile personnel'), style: Theme.of(context).textTheme.headlineMedium),
        const SizedBox(height: 12),
        Text(context.tr(
            'Sentinel assesses what your phone’s operating system lets an app see: configuration weaknesses, risky privileges, known malicious indicators, suspicious links and networks. It tells you how sure it is and what it could not check.',
            'Sentinel évalue ce que le système de votre téléphone permet à une app de voir : faiblesses de configuration, privilèges risqués, indicateurs malveillants connus, liens et réseaux suspects. Il indique son degré de certitude et ce qu’il n’a pas pu vérifier.')),
        const SizedBox(height: 16),
        InfoBanner(context.tr(
            'No mobile security app can guarantee a device is clean. Sentinel never claims a device is “completely safe”.',
            'Aucune app de sécurité mobile ne peut garantir qu’un appareil est sain. Sentinel n’affirme jamais qu’un appareil est « totalement sûr ».'),
            color: SocColors.amber, icon: Icons.warning_amber_rounded),
      ]);

  Widget _privacy(BuildContext context) => ListView(padding: const EdgeInsets.all(24), children: [
        Text(context.tr('Privacy & permissions', 'Confidentialité et autorisations'), style: Theme.of(context).textTheme.headlineSmall),
        const SizedBox(height: 12),
        for (final (icon, en, fr) in [
          (Icons.phone_android, 'Everything runs on your device. Results are encrypted with a key stored in the Android Keystore / iOS Keychain.',
              'Tout s’exécute sur l’appareil. Les résultats sont chiffrés avec une clé du Keystore Android / Trousseau iOS.'),
          (Icons.cloud_off, 'Nothing is sent to any server unless you enable cloud reputation checks; files are never uploaded, only their hash.',
              'Rien n’est envoyé à un serveur sauf si vous activez la réputation cloud ; aucun fichier n’est envoyé, seulement son empreinte.'),
          (Icons.no_accounts, 'Sentinel never asks for contacts, SMS, call log or microphone access, and never records calls.',
              'Sentinel ne demande jamais les contacts, SMS, journal d’appels ni le micro, et n’enregistre jamais les appels.'),
          (Icons.lock_open, 'Permissions are requested only when you use the feature that needs them (e.g. Bluetooth for the tracker scan).',
              'Les autorisations sont demandées uniquement à l’usage de la fonction concernée (ex. Bluetooth pour les traceurs).'),
          (Icons.touch_app, 'Sentinel never uninstalls apps or changes settings by itself: it opens the right system screen and you decide.',
              'Sentinel ne désinstalle rien et ne modifie aucun réglage seul : il ouvre l’écran système adéquat et vous décidez.'),
        ])
          ListTile(contentPadding: EdgeInsets.zero, leading: Icon(icon, color: SocColors.cyan), title: Text(context.tr(en, fr))),
      ]);
}

class CapabilityMatrix extends StatelessWidget {
  const CapabilityMatrix({super.key, required this.platform});
  final DevicePlatform platform;

  @override
  Widget build(BuildContext context) {
    Widget mark(String v, bool current) {
      final (icon, color, label) = switch (v) {
        'yes' => (Icons.check_circle, SocColors.green, context.tr('Supported', 'Pris en charge')),
        'partial' => (Icons.adjust, SocColors.amber, context.tr('Partial', 'Partiel')),
        _ => (Icons.cancel_outlined, SocColors.muted, context.tr('Not possible', 'Impossible')),
      };
      return Icon(icon, color: current ? color : color.withValues(alpha: 0.5), semanticLabel: label, size: 20);
    }

    return ListView(padding: const EdgeInsets.all(24), children: [
      Text(context.tr('What this device lets Sentinel check', 'Ce que cet appareil permet de vérifier'), style: Theme.of(context).textTheme.headlineSmall),
      const SizedBox(height: 8),
      Text(context.tr('Your device: ${platform.name}. Unavailable checks are shown in every report so you can verify them manually.',
          'Votre appareil : ${platform.name}. Les vérifications impossibles apparaissent dans chaque rapport pour un contrôle manuel.'),
          style: const TextStyle(color: SocColors.muted)),
      const SizedBox(height: 12),
      Row(children: [
        const Expanded(child: SizedBox()),
        SizedBox(width: 64, child: Center(child: Text('Android', style: TextStyle(fontWeight: platform == DevicePlatform.android ? FontWeight.w800 : null)))),
        SizedBox(width: 48, child: Center(child: Text('iOS', style: TextStyle(fontWeight: platform == DevicePlatform.ios ? FontWeight.w800 : null)))),
      ]),
      const Divider(),
      for (final c in capabilities)
        Padding(
          padding: const EdgeInsets.symmetric(vertical: 6),
          child: Row(children: [
            Expanded(child: Text(context.lt(c.label))),
            SizedBox(width: 64, child: Center(child: mark(c.android, platform == DevicePlatform.android))),
            SizedBox(width: 48, child: Center(child: mark(c.ios, platform == DevicePlatform.ios))),
          ]),
        ),
    ]);
  }
}
