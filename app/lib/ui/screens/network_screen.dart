import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../core/models.dart';
import '../../core/snapshot.dart';
import '../../detection/common_rules.dart';
import '../../detection/rule.dart';
import '../../engine/network_probe.dart';
import '../../state/app_state.dart';
import '../l10n.dart';
import '../theme.dart';
import '../widgets/common.dart';
import 'finding_detail_screen.dart';

class NetworkScreen extends StatefulWidget {
  const NetworkScreen({super.key});
  @override
  State<NetworkScreen> createState() => _NetworkScreenState();
}

class _NetworkScreenState extends State<NetworkScreen> {
  late Future<DeviceSnapshot> _snap = context.read<AppState>().snapshot();
  bool _probing = false;
  ProbeResult? _probe;

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    return Scaffold(
      appBar: AppBar(title: Text(context.tr('Network security', 'Sécurité réseau')), actions: [
        IconButton(icon: const Icon(Icons.refresh), onPressed: () => setState(() => _snap = state.snapshot())),
      ]),
      body: Responsive(
        child: FutureBuilder<DeviceSnapshot>(
          future: _snap,
          builder: (context, snap) {
            if (snap.hasError) return EmptyState(Icons.error_outline, '${snap.error}');
            if (!snap.hasData) return const Center(child: CircularProgressIndicator());
            final s = snap.data!;
            final n = s.network;
            final ctx = RuleContext(snapshot: s, pack: state.pack);
            final findings = [
              for (final r in commonRules.where((r) => r.platforms.contains(s.platform) && r.id.startsWith('NET'))) ...r.evaluate(ctx),
              ...?_probe?.findings,
            ];
            final proxy = (n['proxy'] ?? s.device['proxy']) as Map?;
            String v(Object? x) => x == null ? context.tr('Not exposed by OS', 'Non exposé par l’OS') : '$x';
            return ListView(padding: const EdgeInsets.all(16), children: [
              Card(
                child: Column(children: [
                  ListTile(title: Text(context.tr('Connection', 'Connexion')), trailing: Text(v(n['transport']))),
                  ListTile(title: Text(context.tr('Wi-Fi security', 'Sécurité Wi-Fi')), trailing: Text(n['transport'] == 'wifi' ? v(n['wifiSecurity']) : '—')),
                  ListTile(title: const Text('VPN'), trailing: Text((n['vpnActive'] ?? s.device['vpnActive']) == true ? context.tr('Active', 'Actif') : context.tr('Inactive', 'Inactif'))),
                  ListTile(title: const Text('Proxy'), trailing: Text(proxy == null ? context.tr('None', 'Aucun') : '${proxy['host'] ?? proxy['pacUrl']}:${proxy['port'] ?? ''}')),
                  if (s.platform == DevicePlatform.android) ...[
                    ListTile(title: Text(context.tr('Private DNS', 'DNS privé')), trailing: Text(n['privateDnsActive'] == null ? v(null) : (n['privateDnsActive'] == true ? '${n['privateDnsServer'] ?? context.tr('Active', 'Actif')}' : context.tr('Off', 'Désactivé')))),
                    ListTile(title: Text(context.tr('Internet validated', 'Internet validé')), trailing: Text(v(n['validated']))),
                    ListTile(title: Text(context.tr('User CA certificates', 'Certificats CA utilisateur')), trailing: Text(v((s.device['userCaCertificates'] as List?)?.length))),
                  ],
                ]),
              ),
              SectionTitle(context.tr('TLS certificate validation', 'Validation des certificats TLS')),
              Text(context.tr('Connects to google.com, cloudflare.com and apple.com with normal validation (never bypassed) to detect interception.',
                  'Se connecte à google.com, cloudflare.com et apple.com avec la validation normale (jamais contournée) pour détecter une interception.'),
                  style: const TextStyle(color: SocColors.muted)),
              const SizedBox(height: 8),
              OutlinedButton.icon(
                onPressed: _probing
                    ? null
                    : () async {
                        setState(() => _probing = true);
                        final r = await NetworkProbe().run(s.platform, DateTime.now());
                        if (mounted) {
                          setState(() {
                            _probe = r;
                            _probing = false;
                          });
                        }
                      },
                icon: _probing ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2)) : const Icon(Icons.https),
                label: Text(context.tr('Run TLS check now', 'Lancer la vérification TLS')),
              ),
              if (_probe != null && _probe!.findings.isEmpty)
                InfoBanner(
                    _probe!.completed
                        ? context.tr('Certificates validated normally for the tested hosts.', 'Certificats validés normalement pour les hôtes testés.')
                        : context.tr('Hosts unreachable — no conclusion.', 'Hôtes injoignables — aucune conclusion.'),
                    color: _probe!.completed ? SocColors.green : SocColors.muted),
              SectionTitle(context.tr('Findings', 'Résultats')),
              if (findings.isEmpty) Text(context.tr('No network risk detected among the checks available.', 'Aucun risque réseau détecté parmi les vérifications disponibles.')),
              for (final f in findings) FindingTile(f, onTap: () => Navigator.push(context, MaterialPageRoute(builder: (_) => FindingDetailScreen(finding: f)))),
              const SizedBox(height: 12),
              InfoBanner(context.tr(
                  'Sentinel does not inspect other apps’ traffic and does not install any VPN or certificate.',
                  'Sentinel n’inspecte pas le trafic des autres apps et n’installe ni VPN ni certificat.')),
            ]);
          },
        ),
      ),
    );
  }
}
