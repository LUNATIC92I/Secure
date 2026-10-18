import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../core/models.dart';
import '../../engine/scoring.dart';
import '../../state/app_state.dart';
import '../l10n.dart';
import '../theme.dart';
import '../widgets/common.dart';
import 'finding_detail_screen.dart';

class ScanResultsScreen extends StatelessWidget {
  const ScanResultsScreen({super.key, required this.report});
  final ScanReport report;

  @override
  Widget build(BuildContext context) {
    context.watch<AppState>();
    final score = SecurityScore.compute(report.findings, report.coverage);
    final byCat = <FindingCategory, List<Finding>>{};
    for (final f in report.findings) {
      byCat.putIfAbsent(f.category, () => []).add(f);
    }
    final unchecked = report.coverage.where((c) => c.status != CoverageStatus.checked && c.status != CoverageStatus.notApplicable).toList();
    return Scaffold(
      appBar: AppBar(title: Text(modeLabel(context, report.mode))),
      body: Responsive(
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Row(
                  children: [
                    if (report.coverage.isNotEmpty) ScoreRing(score: score, size: 110),
                    const SizedBox(width: 16),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(fmtDate(context, report.finishedAt), style: const TextStyle(fontWeight: FontWeight.w700)),
                          Text('ID ${report.id}', style: const TextStyle(color: SocColors.muted, fontSize: 12)),
                          Text(
                            context.tr(
                              '${report.findings.length} finding(s) · rule pack v${report.rulePackVersion}',
                              '${report.findings.length} résultat(s) · pack v${report.rulePackVersion}',
                            ),
                          ),
                          if (report.appsAnalyzed > 0) Text(context.tr('${report.appsAnalyzed} apps analysed', '${report.appsAnalyzed} apps analysées')),
                          if (report.coverage.isNotEmpty)
                            Text(context.tr('Coverage ${(score.coverage * 100).round()}%', 'Couverture ${(score.coverage * 100).round()} %')),
                          if (report.background)
                            Text(context.tr('Background run', 'Exécution en arrière-plan'), style: const TextStyle(color: SocColors.muted)),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
            if (report.errors.isNotEmpty)
              InfoBanner(
                context.tr('Some checks failed: ', 'Certaines vérifications ont échoué : ') + report.errors.join(' · '),
                color: SocColors.red,
                icon: Icons.error_outline,
              ),
            if (report.findings.isEmpty)
              InfoBanner(
                context.tr(
                  'No issues found in the checked areas. Unchecked areas are listed below; a clean result is not proof that the device is safe.',
                  'Aucun problème dans les zones vérifiées. Les zones non vérifiées sont listées ci-dessous ; un résultat propre ne prouve pas que l’appareil est sûr.',
                ),
                color: SocColors.green,
                icon: Icons.verified_outlined,
              ),
            for (final e in byCat.entries) ...[
              SectionTitle('${categoryLabel(context, e.key)} (${e.value.length})'),
              for (final f in e.value)
                FindingTile(
                  f,
                  onTap: () => Navigator.push(context, MaterialPageRoute(builder: (_) => FindingDetailScreen(finding: f))),
                ),
            ],
            if (report.coverage.isNotEmpty) ...[
              SectionTitle(context.tr('Not checked / manual verification', 'Non vérifié / contrôle manuel')),
              if (unchecked.isEmpty) Text(context.tr('All applicable checks ran.', 'Toutes les vérifications applicables ont été exécutées.')),
              CoverageList(unchecked),
              ExpansionTile(
                tilePadding: EdgeInsets.zero,
                title: Text(
                  context.tr(
                    'Checks performed (${report.coverage.length - unchecked.length})',
                    'Vérifications effectuées (${report.coverage.length - unchecked.length})',
                  ),
                ),
                children: [CoverageList(report.coverage.where((c) => c.status == CoverageStatus.checked).toList())],
              ),
            ],
          ],
        ),
      ),
    );
  }
}
