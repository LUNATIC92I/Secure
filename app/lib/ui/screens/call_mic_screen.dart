import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../core/models.dart';
import '../../core/snapshot.dart';
import '../../detection/permissions.dart';
import '../../state/app_state.dart';
import '../l10n.dart';
import '../theme.dart';
import '../widgets/common.dart';

/// Call & Microphone Security Monitor.
///
/// Keeps six levels of evidence apart: permission granted, actual access, OS indicator,
/// suspicious configuration, evidence of capture, suspected call interception.
class CallMicScreen extends StatefulWidget {
  const CallMicScreen({super.key});
  @override
  State<CallMicScreen> createState() => _CallMicScreenState();
}

class _CallMicScreenState extends State<CallMicScreen> {
  late Future<DeviceSnapshot> _snap = context.read<AppState>().snapshot(apps: true);

  @override
  Widget build(BuildContext context) {
    final state = context.read<AppState>();
    final android = state.platform == DevicePlatform.android;
    return Scaffold(
      appBar: AppBar(title: Text(context.tr('Call & microphone security', 'Sécurité appels et micro'))),
      body: Responsive(
        child: FutureBuilder<DeviceSnapshot>(
          future: _snap,
          builder: (context, snap) {
            if (snap.hasError) return EmptyState(Icons.error_outline, '${snap.error}');
            if (!snap.hasData) return const Center(child: CircularProgressIndicator());
            final s = snap.data!;
            final micApps = s.apps.where((a) => !a.isSystem && a.granted(permRecordAudio)).toList();
            final accessibility = s.list('accessibilityServices').where((a) => a['isSystem'] != true).toList();
            final admins = s.list('deviceAdmins');
            final vpn = s.network['vpnActive'] == true || s.device['vpnActive'] == true;
            final proxy = s.network['proxy'] ?? s.device['proxy'];
            return ListView(padding: const EdgeInsets.all(16), children: [
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Row(children: [
                      const Icon(Icons.help_outline, color: SocColors.amber),
                      const SizedBox(width: 8),
                      Expanded(child: Text(context.tr('Is my call being intercepted?', 'Mon appel est-il intercepté ?'), style: const TextStyle(fontWeight: FontWeight.w700))),
                    ]),
                    const SizedBox(height: 8),
                    Text(context.tr(
                        'Unable to verify whether this call is being intercepted. No conclusion can be drawn from the available device indicators.',
                        'Impossible de vérifier si cet appel est intercepté. Aucune conclusion ne peut être tirée des indicateurs disponibles sur l’appareil.'),
                        style: const TextStyle(height: 1.4)),
                    const SizedBox(height: 8),
                    Text(context.tr(
                        'Carrier-level interception, SS7 abuse and IMSI catchers are invisible to apps. Poor call quality, battery drain or heat are not evidence of eavesdropping.',
                        'L’interception côté opérateur, l’abus SS7 et les IMSI-catchers sont invisibles pour les apps. Mauvaise qualité d’appel, batterie ou chauffe ne prouvent pas une écoute.'),
                        style: const TextStyle(color: SocColors.muted)),
                  ]),
                ),
              ),
              SectionTitle(context.tr('Evidence levels on this device', 'Niveaux de preuve sur cet appareil')),
              _level(context, 1, context.tr('Microphone permission granted', 'Autorisation micro accordée'),
                  android ? context.tr('${micApps.length} third-party app(s)', '${micApps.length} app(s) tierce(s)') : context.tr('Not visible on iOS', 'Non visible sur iOS'),
                  android ? (micApps.isEmpty ? _St.ok : _St.info) : _St.unknown),
              _level(context, 2, context.tr('An app actually accessed the microphone', 'Une app a réellement utilisé le micro'),
                  context.tr('Only the system can show this — open the Privacy Dashboard / App Privacy Report', 'Seul le système peut l’afficher — tableau de bord de confidentialité / Rapport de confidentialité'),
                  _St.unknown),
              _level(context, 3, context.tr('OS privacy indicator', 'Indicateur de confidentialité'),
                  context.tr('Green (Android) or orange (iOS) dot at the top of the screen while the mic is in use. Pull down Control Center / quick settings to see which app.',
                      'Point vert (Android) ou orange (iOS) en haut de l’écran pendant l’usage du micro. Ouvrez le centre de contrôle / réglages rapides pour voir l’app.'),
                  _St.info),
              _level(
                  context,
                  4,
                  context.tr('Suspicious monitoring configuration', 'Configuration de surveillance suspecte'),
                  [
                    if (android) context.tr('${accessibility.length} accessibility service(s)', '${accessibility.length} service(s) d’accessibilité'),
                    if (android) context.tr('${admins.length} device admin(s)', '${admins.length} administrateur(s)'),
                    vpn ? context.tr('VPN active', 'VPN actif') : context.tr('no VPN', 'pas de VPN'),
                    proxy != null ? context.tr('proxy set', 'proxy configuré') : context.tr('no proxy', 'pas de proxy'),
                  ].join(' · '),
                  accessibility.isNotEmpty || proxy != null ? _St.warn : _St.ok),
              _level(context, 5, context.tr('Evidence of unauthorised audio capture', 'Preuve de capture audio non autorisée'),
                  context.tr('Not observable by apps. A forensic examination (e.g. MVT by Amnesty Tech) is needed.', 'Non observable par une app. Une expertise (ex. MVT d’Amnesty Tech) est nécessaire.'),
                  _St.unknown),
              _level(context, 6, context.tr('Interception of phone calls', 'Interception des appels'),
                  context.tr('Cannot be verified from the device.', 'Impossible à vérifier depuis l’appareil.'), _St.unknown),
              if (android) ...[
                SectionTitle(context.tr('Apps that can use the microphone', 'Apps pouvant utiliser le micro')),
                if (micApps.isEmpty) Text(context.tr('None among third-party apps.', 'Aucune parmi les apps tierces.')),
                for (final a in micApps)
                  ListTile(
                    dense: true,
                    leading: Icon(Icons.mic, color: a.isSideloaded || !a.hasLauncher ? SocColors.amber : SocColors.muted),
                    title: Text(a.label),
                    subtitle: Text([if (a.isSideloaded) context.tr('outside store', 'hors store'), if (!a.hasLauncher) context.tr('no icon', 'sans icône')].join(' · ')),
                    trailing: TextButton(onPressed: () => state.native.openSettings('appDetails', package: a.package), child: Text(context.tr('Revoke', 'Révoquer'))),
                  ),
              ],
              SectionTitle(context.tr('Check now', 'Vérifier maintenant')),
              if (android)
                ListTile(
                  leading: const Icon(Icons.privacy_tip_outlined),
                  title: Text(context.tr('Open Privacy Dashboard (recent microphone use)', 'Ouvrir le tableau de bord de confidentialité')),
                  onTap: () => state.native.openSettings('privacyDashboard'),
                )
              else
                ListTile(
                  leading: const Icon(Icons.privacy_tip_outlined),
                  title: Text(context.tr('Settings → Privacy & Security → App Privacy Report', 'Réglages → Confidentialité et sécurité → Rapport de confidentialité des apps')),
                  subtitle: Text(context.tr('Also: Privacy & Security → Microphone to see which apps have access.', 'Aussi : Confidentialité et sécurité → Micro pour voir les apps autorisées.')),
                ),
              ListTile(
                leading: const Icon(Icons.phone_forwarded),
                title: Text(context.tr('Check call forwarding (*#21#)', 'Vérifier le renvoi d’appel (*#21#)')),
                subtitle: Text(android
                    ? context.tr('Opens the dialer pre-filled; you press call. Standard GSM code — your carrier replies with the forwarding status. *#62# and *#67# check conditional forwarding.',
                        'Ouvre le composeur prérempli ; vous appuyez sur appeler. Code GSM standard — l’opérateur indique l’état du renvoi. *#62# et *#67# pour les renvois conditionnels.')
                    : context.tr('iOS does not allow apps to pre-fill these codes: type *#21# in the Phone app, or see Settings → Phone → Call Forwarding.',
                        'iOS n’autorise pas le préremplissage : tapez *#21# dans Téléphone ou voyez Réglages → Téléphone → Renvoi d’appel.')),
                onTap: android ? () => state.native.openDialer('*#21#') : null,
              ),
              InfoBanner(context.tr(
                  'If forwarding is active and you did not set it, disable it (##002# on most GSM networks) and contact your carrier: it can indicate SIM-swap or account compromise.',
                  'Si un renvoi est actif sans votre accord, désactivez-le (##002# sur la plupart des réseaux GSM) et contactez votre opérateur : cela peut indiquer un SIM-swap ou une compromission de compte.'),
                  color: SocColors.amber, icon: Icons.warning_amber_rounded),
              const SizedBox(height: 8),
              Text(context.tr('Sentinel never records calls or captures audio.', 'Sentinel n’enregistre jamais les appels et ne capte aucun son.'),
                  style: const TextStyle(color: SocColors.muted), textAlign: TextAlign.center),
              TextButton(onPressed: () => setState(() => _snap = state.snapshot(apps: true)), child: Text(context.tr('Refresh', 'Actualiser'))),
            ]);
          },
        ),
      ),
    );
  }

  Widget _level(BuildContext context, int n, String title, String detail, _St st) {
    final (icon, color, label) = switch (st) {
      _St.ok => (Icons.check_circle, SocColors.green, context.tr('Nothing notable', 'Rien de notable')),
      _St.info => (Icons.info, SocColors.cyan, context.tr('Informational', 'Information')),
      _St.warn => (Icons.warning_amber, SocColors.amber, context.tr('Review', 'À examiner')),
      _St.unknown => (Icons.visibility_off, SocColors.muted, context.tr('Cannot be verified by an app', 'Invérifiable par une app')),
    };
    return Card(
      child: ListTile(
        leading: CircleAvatar(radius: 14, backgroundColor: SocColors.graphite2, child: Text('$n', style: const TextStyle(fontSize: 12))),
        title: Text(title),
        subtitle: Text(detail),
        trailing: Tooltip(message: label, child: Icon(icon, color: color, semanticLabel: label)),
      ),
    );
  }
}

enum _St { ok, info, warn, unknown }
