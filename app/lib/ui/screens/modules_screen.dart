import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../core/models.dart';
import '../../state/app_state.dart';
import '../l10n.dart';
import '../theme.dart';
import '../widgets/common.dart';
import 'apk_screen.dart';
import 'apps_screen.dart';
import 'call_mic_screen.dart';
import 'network_screen.dart';
import 'phishing_screen.dart';
import 'reports_screen.dart';
import 'tracking_screen.dart';

class ModulesScreen extends StatelessWidget {
  const ModulesScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final android = context.watch<AppState>().platform == DevicePlatform.android;
    final modules = <(IconData, String, String, Widget, bool)>[
      (
        Icons.apps_outage,
        context.tr('Application risk', 'Risque des applications'),
        context.tr('Permissions, install source, privileged access', 'Autorisations, source, accès privilégiés'),
        const AppsScreen(),
        android,
      ),
      (
        Icons.mic_external_on,
        context.tr('Call & microphone', 'Appels et micro'),
        context.tr('Microphone access, call forwarding, monitoring indicators', 'Accès micro, renvoi d’appel, indicateurs de surveillance'),
        const CallMicScreen(),
        true,
      ),
      (
        Icons.location_searching,
        context.tr('Tracking & location', 'Pistage et localisation'),
        context.tr('Location access, Bluetooth trackers', 'Accès localisation, traceurs Bluetooth'),
        const TrackingScreen(),
        true,
      ),
      (
        Icons.wifi_lock,
        context.tr('Network security', 'Sécurité réseau'),
        context.tr('Wi-Fi, VPN, proxy, DNS, TLS', 'Wi-Fi, VPN, proxy, DNS, TLS'),
        const NetworkScreen(),
        true,
      ),
      (
        Icons.phishing,
        context.tr('Phishing scanner', 'Anti-hameçonnage'),
        context.tr('Check a link before opening it', 'Vérifier un lien avant de l’ouvrir'),
        const PhishingScreen(),
        true,
      ),
      (
        Icons.android,
        context.tr('APK analysis', 'Analyse d’APK'),
        context.tr('Static analysis of an APK file you select', 'Analyse statique d’un fichier APK choisi'),
        const ApkScreen(),
        android,
      ),
      (
        Icons.summarize_outlined,
        context.tr('Security reports', 'Rapports de sécurité'),
        context.tr('Export your posture report', 'Exporter votre rapport de posture'),
        const ReportsScreen(),
        true,
      ),
    ];
    return Scaffold(
      appBar: AppBar(title: Text(context.tr('Security modules', 'Modules de sécurité'))),
      body: Responsive(
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            for (final (icon, title, sub, page, enabled) in modules)
              Card(
                child: ListTile(
                  enabled: enabled,
                  leading: CircleAvatar(
                    backgroundColor: SocColors.blue.withValues(alpha: 0.18),
                    child: Icon(icon, color: enabled ? SocColors.cyan : SocColors.muted),
                  ),
                  title: Text(title),
                  subtitle: Text(enabled ? sub : context.tr('Not available on iOS (sandbox restriction)', 'Indisponible sur iOS (restriction du bac à sable)')),
                  trailing: const Icon(Icons.chevron_right),
                  onTap: enabled ? () => Navigator.push(context, MaterialPageRoute(builder: (_) => page)) : null,
                ),
              ),
          ],
        ),
      ),
    );
  }
}
