import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../core/models.dart';
import '../../core/snapshot.dart';
import '../../detection/permissions.dart';
import '../../engine/tracker_assessor.dart';
import '../../state/app_state.dart';
import '../l10n.dart';
import '../theme.dart';
import '../widgets/common.dart';
import 'finding_detail_screen.dart';

class TrackingScreen extends StatefulWidget {
  const TrackingScreen({super.key});
  @override
  State<TrackingScreen> createState() => _TrackingScreenState();
}

class _TrackingScreenState extends State<TrackingScreen> {
  late final Future<DeviceSnapshot> _snap = context.read<AppState>().snapshot(apps: true);
  bool _scanning = false;
  String? _status;
  List<Finding> _found = [];

  Future<void> _scan() async {
    final state = context.read<AppState>();
    final ok = await showDialog<bool>(
      context: context,
      builder: (c) => AlertDialog(
        title: Text(c.tr('Scan for Bluetooth trackers', 'Rechercher des traceurs Bluetooth')),
        content: Text(c.tr(
            'Sentinel will listen for nearby tracker advertisements for 12 seconds. It needs Bluetooth scan permission; results stay on this device and are not used to locate you.',
            'Sentinel écoutera les signaux de traceurs proches pendant 12 secondes. L’autorisation de scan Bluetooth est nécessaire ; les résultats restent sur l’appareil et ne servent pas à vous localiser.')),
        actions: [
          TextButton(onPressed: () => Navigator.pop(c, false), child: Text(c.tr('Cancel', 'Annuler'))),
          FilledButton(onPressed: () => Navigator.pop(c, true), child: Text(c.tr('Scan', 'Rechercher'))),
        ],
      ),
    );
    if (ok != true) return;
    setState(() => _scanning = true);
    try {
      final (status, findings) = await state.scanTrackers();
      setState(() {
        _status = status;
        _found = findings;
      });
    } catch (e) {
      setState(() => _status = '$e');
    } finally {
      if (mounted) setState(() => _scanning = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final ios = state.platform == DevicePlatform.ios;
    return Scaffold(
      appBar: AppBar(title: Text(context.tr('Tracking & location privacy', 'Pistage et localisation'))),
      body: Responsive(
        child: ListView(padding: const EdgeInsets.all(16), children: [
          SectionTitle(context.tr('Bluetooth trackers nearby', 'Traceurs Bluetooth à proximité')),
          InfoBanner(ios
              ? context.tr('iOS hides Apple Find My signals from apps; rely on iOS “Tracking Notifications” for AirTags. Sentinel can detect Tile, SmartTag and Find My Device network tags.',
                  'iOS masque les signaux Localiser d’Apple aux apps ; fiez-vous aux « Notifications de suivi » d’iOS pour les AirTags. Sentinel détecte Tile, SmartTag et balises Localiser mon appareil.')
              : context.tr('Detects AirTag-type (Find My, separated), SmartTag, Tile and Find My Device tags. Not universal: GPS trackers with SIM cards are invisible. Also use Android’s Unknown tracker alerts.',
                  'Détecte les balises type AirTag (séparées), SmartTag, Tile et Localiser mon appareil. Pas universel : les traceurs GPS à carte SIM sont invisibles. Utilisez aussi les alertes de traceurs inconnus d’Android.')),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(children: [
                if (_scanning) const ScanRadar(size: 120),
                if (_status != null && _status != 'ok')
                  Text(switch (_status) {
                    'permissionDenied' => context.tr('Bluetooth scan permission denied.', 'Autorisation Bluetooth refusée.'),
                    'bluetoothOff' => context.tr('Bluetooth is off. Turn it on to scan.', 'Le Bluetooth est désactivé.'),
                    'unsupported' => context.tr('Bluetooth LE not available on this device.', 'Bluetooth LE indisponible.'),
                    _ => context.tr('Scan failed: $_status', 'Échec : $_status'),
                  }),
                if (_status == 'ok' && _found.isEmpty)
                  Text(context.tr('No known tracker signal received during this scan. This does not rule out tracking.',
                      'Aucun signal de traceur connu pendant ce scan. Cela n’exclut pas un pistage.')),
                for (final f in _found) FindingTile(f, onTap: () => Navigator.push(context, MaterialPageRoute(builder: (_) => FindingDetailScreen(finding: f)))),
                const SizedBox(height: 8),
                FilledButton.icon(onPressed: _scanning ? null : _scan, icon: const Icon(Icons.bluetooth_searching), label: Text(context.tr('Scan now', 'Rechercher'))),
                const SizedBox(height: 4),
                Text(context.tr('Tip: scan again after moving to another place. A tracker seen in both places is the meaningful signal.',
                    'Astuce : rescannez après vous être déplacé. Un traceur vu aux deux endroits est le signal pertinent.'),
                    style: const TextStyle(color: SocColors.muted, fontSize: 12), textAlign: TextAlign.center),
              ]),
            ),
          ),
          if (state.trackers.isNotEmpty) ...[
            SectionTitle(context.tr('Recent sightings (3 days)', 'Observations récentes (3 jours)')),
            for (final t in state.trackers)
              ListTile(
                dense: true,
                leading: const Icon(Icons.sensors),
                title: Text(context.lt(TrackerAssessor.kindLabels[t.kind] ?? LText(t.kind, t.kind))),
                subtitle: Text('${t.address} · ${context.tr('${t.scans} scan(s)', '${t.scans} scan(s)')} · ${ago(context, t.lastSeen)}'),
              ),
          ],
          SectionTitle(context.tr('Apps with location access', 'Apps ayant accès à la localisation')),
          if (ios)
            Text(context.tr('Review in Settings → Privacy & Security → Location Services. Use Safety Check to review shared locations (Find My, Messages).',
                'Vérifiez Réglages → Confidentialité et sécurité → Service de localisation. Utilisez Contrôle de sécurité pour les partages de position.'))
          else
            FutureBuilder<DeviceSnapshot>(
              future: _snap,
              builder: (context, snap) {
                if (!snap.hasData) return const LinearProgressIndicator();
                final apps = snap.data!.apps.where((a) => !a.isSystem && (a.granted(permFineLocation) || a.granted(permCoarseLocation))).toList()
                  ..sort((a, b) => (b.granted(permBackgroundLocation) ? 1 : 0).compareTo(a.granted(permBackgroundLocation) ? 1 : 0));
                if (apps.isEmpty) return Text(context.tr('No third-party app has location access.', 'Aucune app tierce n’a accès à la localisation.'));
                return Column(children: [
                  for (final a in apps)
                    ListTile(
                      dense: true,
                      leading: Icon(a.granted(permBackgroundLocation) ? Icons.location_on : Icons.location_on_outlined,
                          color: a.granted(permBackgroundLocation) ? SocColors.amber : SocColors.muted),
                      title: Text(a.label),
                      subtitle: Text([
                        a.granted(permFineLocation) ? context.tr('precise', 'précise') : context.tr('approximate', 'approximative'),
                        a.granted(permBackgroundLocation) ? context.tr('all the time', 'toujours') : context.tr('while in use', 'pendant l’utilisation'),
                        if (a.granted(permBluetoothScan) || a.granted(permNearbyWifi)) context.tr('nearby devices', 'appareils à proximité'),
                      ].join(' · ')),
                      onTap: () => state.native.openSettings('appDetails', package: a.package),
                    ),
                ]);
              },
            ),
          SectionTitle(context.tr('Native protections', 'Protections natives')),
          if (!ios) ...[
            ListTile(leading: const Icon(Icons.location_on), title: Text(context.tr('Location settings', 'Réglages de localisation')), onTap: () => state.native.openSettings('location')),
            ListTile(
              leading: const Icon(Icons.health_and_safety_outlined),
              title: Text(context.tr('Unknown tracker alerts', 'Alertes de traceurs inconnus')),
              subtitle: Text(context.tr('Settings → Safety & emergency → Unknown tracker alerts', 'Paramètres → Sécurité et urgence → Alertes de traceurs inconnus')),
              onTap: () => state.native.openSettings('safetyCenter'),
            ),
          ] else
            ListTile(
              leading: const Icon(Icons.health_and_safety_outlined),
              title: Text(context.tr('Safety Check & Tracking Notifications', 'Contrôle de sécurité et notifications de suivi')),
              subtitle: Text(context.tr('Settings → Privacy & Security → Safety Check; Find My → Me → Tracking Notifications',
                  'Réglages → Confidentialité et sécurité → Contrôle de sécurité ; Localiser → Moi → Notifications de suivi')),
            ),
        ]),
      ),
    );
  }
}
