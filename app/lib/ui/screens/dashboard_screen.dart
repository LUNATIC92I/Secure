import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../core/models.dart';
import '../../state/app_state.dart';
import '../l10n.dart';
import '../theme.dart';
import '../widgets/common.dart';
import 'finding_detail_screen.dart';
import 'scan_results_screen.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key, required this.onNavigate});
  final ValueChanged<int> onNavigate;
  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  Severity? _filter;

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final report = state.lastFullReport;
    final score = state.score;
    final active = state.activeFindings;
    final shown = _filter == null ? active : active.where((f) => f.severity == _filter).toList();
    int count(bool Function(Finding) t) => active.where(t).length;

    return Scaffold(
      appBar: AppBar(
        title: Text(state.settings.brandName),
        actions: [
          IconButton(
            tooltip: context.tr('Run quick scan', 'Lancer une analyse rapide'),
            onPressed: state.scanning ? null : () => state.runScan(ScanMode.quick),
            icon: const Icon(Icons.bolt),
          ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: () async => state.runScan(ScanMode.quick),
        child: Responsive(
          child: ListView(
            padding: const EdgeInsets.all(16),
            children: [
              if (state.loadError != null) InfoBanner(state.loadError!, color: SocColors.red, icon: Icons.error_outline),
              if (state.assessmentOverdue)
                InfoBanner(
                  context.tr(
                    'Daily assessment is overdue: the OS did not run it in the background. Run a scan now.',
                    'L’évaluation quotidienne est en retard : l’OS ne l’a pas exécutée en arrière-plan. Lancez une analyse.',
                  ),
                  color: SocColors.amber,
                  icon: Icons.schedule,
                ),
              _header(context, state),
              if (report != null) ...[
                const SizedBox(height: 8),
                _metricsGrid(context, [
                  (context.tr('Confirmed threats', 'Menaces confirmées'), count((f) => f.classification == Classification.confirmedMalicious), SocColors.red),
                  (context.tr('Suspicious', 'Suspects'), count((f) => f.classification == Classification.suspicious), SocColors.amber),
                  (context.tr('Config. weaknesses', 'Faiblesses config.'), count((f) => f.classification == Classification.exposure), SocColors.cyan),
                  (context.tr('To verify', 'À vérifier'), count((f) => f.classification == Classification.unverified), SocColors.purple),
                  (
                    context.tr('Apps to review', 'Apps à revoir'),
                    active
                        .where((f) => const {FindingCategory.permissions, FindingCategory.stalkerware, FindingCategory.malware}.contains(f.category))
                        .map((f) => f.component)
                        .toSet()
                        .length,
                    SocColors.blue,
                  ),
                  (
                    context.tr('Network risks', 'Risques réseau'),
                    count((f) => f.category == FindingCategory.network && f.severity != Severity.informational),
                    SocColors.blue,
                  ),
                  (
                    context.tr('Privacy / tracking', 'Vie privée / pistage'),
                    count((f) => (f.category == FindingCategory.tracking || f.category == FindingCategory.privacy || f.category == FindingCategory.microphone)),
                    SocColors.blue,
                  ),
                  (context.tr('Apps analysed', 'Apps analysées'), report.appsAnalyzed, SocColors.muted),
                ]),
                SectionTitle(
                  context.tr('Threat severity', 'Gravité des menaces'),
                  trailing: _filter == null ? null : TextButton(onPressed: () => setState(() => _filter = null), child: Text(context.tr('Clear', 'Effacer'))),
                ),
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(12),
                    child: SeverityBars(findings: active, selected: _filter, onSelect: (s) => setState(() => _filter = s)),
                  ),
                ),
                SectionTitle(context.tr('Recommended actions', 'Actions recommandées')),
                if (shown.isEmpty)
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: Text(
                        context.tr(
                          'No issues detected in the areas that could be checked (coverage ${((score?.coverage ?? 0) * 100).round()}%). This is not a guarantee: see unchecked areas in the last report.',
                          'Aucun problème détecté dans les zones vérifiables (couverture ${((score?.coverage ?? 0) * 100).round()} %). Ce n’est pas une garantie : voir les zones non vérifiées dans le dernier rapport.',
                        ),
                      ),
                    ),
                  ),
                for (final f in shown.take(6))
                  FindingTile(
                    f,
                    onTap: () => Navigator.push(context, MaterialPageRoute(builder: (_) => FindingDetailScreen(finding: f))),
                  ),
                if (shown.length > 6)
                  TextButton(
                    onPressed: () => Navigator.push(context, MaterialPageRoute(builder: (_) => ScanResultsScreen(report: report))),
                    child: Text(context.tr('See all ${shown.length} findings', 'Voir les ${shown.length} résultats')),
                  ),
                SectionTitle(context.tr('Recent security events', 'Événements récents')),
                _timeline(context, state),
              ] else
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(20),
                    child: Column(
                      children: [
                        Text(
                          context.tr(
                            'No assessment yet. Run your first scan to see your security posture.',
                            'Aucune évaluation. Lancez une première analyse pour voir votre posture de sécurité.',
                          ),
                        ),
                        const SizedBox(height: 12),
                        FilledButton.icon(
                          onPressed: state.scanning ? null : () => state.runScan(ScanMode.comprehensive),
                          icon: const Icon(Icons.radar),
                          label: Text(context.tr('Run comprehensive scan', 'Lancer l’analyse complète')),
                        ),
                      ],
                    ),
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _header(BuildContext context, AppState state) {
    final report = state.lastFullReport;
    final score = state.score;
    final wide = MediaQuery.sizeOf(context).width > 600;
    final info = Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(context.tr('Security posture', 'Posture de sécurité'), style: const TextStyle(color: SocColors.muted)),
        const SizedBox(height: 4),
        if (state.scanning) ...[
          Text(context.lt(state.progress?.stage ?? const LText('Scanning', 'Analyse')), style: const TextStyle(fontWeight: FontWeight.w700)),
          const SizedBox(height: 8),
          LinearProgressIndicator(value: state.progress?.fraction),
        ] else ...[
          Text(
            report == null ? context.tr('Never scanned', 'Jamais analysé') : '${modeLabel(context, report.mode)} · ${ago(context, report.finishedAt)}',
            style: const TextStyle(fontWeight: FontWeight.w700),
          ),
          if (report?.background == true)
            Text(context.tr('Run by the OS scheduler', 'Exécutée par le planificateur de l’OS'), style: const TextStyle(color: SocColors.muted)),
        ],
        const SizedBox(height: 8),
        if (score != null)
          Text(
            context.tr(
              'Coverage: ${(score.coverage * 100).round()}% of applicable checks',
              'Couverture : ${(score.coverage * 100).round()} % des vérifications',
            ),
            style: const TextStyle(color: SocColors.muted),
          ),
        Text(
          state.settings.dailyAssessment
              ? context.tr('Daily assessment: on (timing decided by the OS)', 'Évaluation quotidienne : active (horaire décidé par l’OS)')
              : context.tr('Daily assessment: off', 'Évaluation quotidienne : désactivée'),
          style: const TextStyle(color: SocColors.muted),
        ),
        Text(
          context.tr(
            'Rule pack v${state.pack.version}${state.pack.verified ? ' · signature verified' : ''}',
            'Pack de règles v${state.pack.version}${state.pack.verified ? ' · signature vérifiée' : ''}',
          ),
          style: const TextStyle(color: SocColors.muted),
        ),
        if (report != null)
          TextButton(
            onPressed: () => Navigator.push(context, MaterialPageRoute(builder: (_) => ScanResultsScreen(report: report))),
            child: Text(context.tr('Open last report', 'Ouvrir le dernier rapport')),
          ),
      ],
    );
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: wide
            ? Row(
                children: [
                  state.scanning ? const ScanRadar() : ScoreRing(score: score),
                  const SizedBox(width: 24),
                  Expanded(child: info),
                ],
              )
            : Column(
                children: [
                  state.scanning ? const ScanRadar() : ScoreRing(score: score),
                  const SizedBox(height: 16),
                  info,
                ],
              ),
      ),
    );
  }

  Widget _metricsGrid(BuildContext context, List<(String, int, Color)> items) => LayoutBuilder(
    builder: (context, c) {
      final cols = c.maxWidth > 600 ? 4 : 2;
      // Fixed tile height scales with the user's text size so labels never clip.
      final height = 52 + 34 * MediaQuery.textScalerOf(context).scale(1);
      return GridView(
        shrinkWrap: true,
        physics: const NeverScrollableScrollPhysics(),
        gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(crossAxisCount: cols, mainAxisExtent: height, mainAxisSpacing: 8, crossAxisSpacing: 8),
        children: [
          for (final (label, n, color) in items)
            Semantics(
              label: '$label: $n',
              excludeSemantics: true,
              child: Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: SocColors.graphite,
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: SocColors.line),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Text(
                      '$n',
                      style: TextStyle(fontSize: 22, fontWeight: FontWeight.w800, color: n > 0 ? color : SocColors.silver),
                    ),
                    Text(
                      label,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(fontSize: 12, color: SocColors.muted),
                    ),
                  ],
                ),
              ),
            ),
        ],
      );
    },
  );

  Widget _timeline(BuildContext context, AppState state) {
    final events = <(DateTime, String, Color)>[];
    for (final r in state.reports.take(10)) {
      final n = r.findings.where((f) => f.isActive && f.severity.index >= Severity.medium.index).length;
      events.add((
        r.finishedAt,
        '${modeLabel(context, r.mode)} — ${context.tr('$n notable finding(s)', '$n résultat(s) notable(s)')}',
        n > 0 ? SocColors.amber : SocColors.green,
      ));
    }
    for (final i in state.incidents.values) {
      for (final t in i.timeline) {
        events.add((t.at, '${i.id}: ${context.lt(t.text)}', SocColors.severity(i.finding.severity)));
      }
    }
    events.sort((a, b) => b.$1.compareTo(a.$1));
    if (events.isEmpty) return EmptyState(Icons.timeline, context.tr('No events yet', 'Aucun événement'));
    return Card(
      child: Column(
        children: [
          for (final e in events.take(8))
            ListTile(
              dense: true,
              leading: Icon(Icons.circle, size: 10, color: e.$3),
              title: Text(e.$2),
              subtitle: Text(fmtDate(context, e.$1), style: const TextStyle(color: SocColors.muted)),
            ),
        ],
      ),
    );
  }
}
