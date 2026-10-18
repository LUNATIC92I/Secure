import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../core/models.dart';
import '../../state/app_state.dart';
import '../l10n.dart';
import '../theme.dart';
import '../widgets/common.dart';
import 'history_screen.dart';
import 'scan_results_screen.dart';

class ScanScreen extends StatelessWidget {
  const ScanScreen({super.key});

  Future<void> _run(BuildContext context, ScanMode mode) async {
    final state = context.read<AppState>();
    final r = await state.runScan(mode);
    if (r != null && context.mounted) {
      await Navigator.push(context, MaterialPageRoute(builder: (_) => ScanResultsScreen(report: r)));
    }
  }

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final ios = state.platform == DevicePlatform.ios;
    return Scaffold(
      appBar: AppBar(
        title: Text(context.tr('Security scan', 'Analyse de sécurité')),
        actions: [
          IconButton(
            tooltip: context.tr('Scan history', 'Historique'),
            icon: const Icon(Icons.history),
            onPressed: () => Navigator.push(context, MaterialPageRoute(builder: (_) => const HistoryScreen())),
          ),
        ],
      ),
      body: Responsive(
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            if (state.scanning)
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(24),
                  child: Column(
                    children: [
                      const ScanRadar(size: 180),
                      const SizedBox(height: 16),
                      Text(modeLabel(context, state.scanningMode!), style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 18)),
                      const SizedBox(height: 8),
                      Semantics(
                        liveRegion: true,
                        child: Text(context.lt(state.progress?.stage ?? const LText('Starting', 'Démarrage')), style: const TextStyle(color: SocColors.muted)),
                      ),
                      const SizedBox(height: 12),
                      LinearProgressIndicator(value: state.progress?.fraction),
                    ],
                  ),
                ),
              )
            else ...[
              _modeCard(
                context,
                icon: Icons.bolt,
                title: context.tr('Quick scan', 'Analyse rapide'),
                body: context.tr(
                  'Configuration, integrity, privileged access (accessibility, device admin, notification access), VPN/proxy/certificates, known indicators and stalkerware correlation.',
                  'Configuration, intégrité, accès privilégiés (accessibilité, administrateurs, notifications), VPN/proxy/certificats, indicateurs connus et corrélation stalkerware.',
                ),
                onTap: () => _run(context, ScanMode.quick),
              ),
              _modeCard(
                context,
                icon: Icons.radar,
                title: context.tr('Comprehensive scan', 'Analyse complète'),
                body: context.tr(
                  'Everything in the quick scan plus per-app review (side-loaded apps, debuggable apps, install permissions, background location), DNS and optional TLS validation.',
                  'Tout le contenu rapide plus revue par app (hors store, débogables, installation, localisation en arrière-plan), DNS et validation TLS optionnelle.',
                ),
                onTap: () => _run(context, ScanMode.comprehensive),
              ),
              if (ios)
                InfoBanner(
                  context.tr(
                    'On iOS, apps cannot list or inspect other apps. Scans cover device configuration, integrity indicators and network; the report lists what to check manually.',
                    'Sur iOS, une app ne peut ni lister ni inspecter les autres apps. Les analyses couvrent la configuration, l’intégrité et le réseau ; le rapport liste les contrôles manuels.',
                  ),
                ),
            ],
            SectionTitle(context.tr('Daily assessment', 'Évaluation quotidienne')),
            Card(
              child: SwitchListTile(
                value: state.settings.dailyAssessment,
                onChanged: (v) => state.updateSettings((s) => s.dailyAssessment = v),
                title: Text(context.tr('Run a quick assessment about once a day', 'Lancer une évaluation rapide environ une fois par jour')),
                subtitle: Text(
                  ios
                      ? context.tr(
                          'iOS decides if and when background refresh runs; it is not guaranteed daily.',
                          'iOS décide si et quand l’actualisation en arrière-plan s’exécute ; pas garanti chaque jour.',
                        )
                      : context.tr(
                          'Android WorkManager, battery-friendly; may be delayed by battery optimisation.',
                          'WorkManager Android, économe en batterie ; peut être retardé par l’optimisation de batterie.',
                        ),
                ),
              ),
            ),
            if (state.lastFullReport != null)
              ListTile(
                leading: const Icon(Icons.event_available),
                title: Text(context.tr('Last completed scan', 'Dernière analyse terminée')),
                subtitle: Text('${fmtDate(context, state.lastFullReport!.finishedAt)} · ${modeLabel(context, state.lastFullReport!.mode)}'),
              ),
          ],
        ),
      ),
    );
  }

  Widget _modeCard(BuildContext context, {required IconData icon, required String title, required String body, required VoidCallback onTap}) => Card(
    child: InkWell(
      borderRadius: BorderRadius.circular(14),
      onTap: onTap,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            CircleAvatar(
              radius: 26,
              backgroundColor: SocColors.blue.withValues(alpha: 0.2),
              child: Icon(icon, color: SocColors.cyan),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(title, style: const TextStyle(fontSize: 17, fontWeight: FontWeight.w700)),
                  const SizedBox(height: 4),
                  Text(body, style: const TextStyle(color: SocColors.muted)),
                ],
              ),
            ),
            const Icon(Icons.play_arrow, color: SocColors.cyan),
          ],
        ),
      ),
    ),
  );
}
