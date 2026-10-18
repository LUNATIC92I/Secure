import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../core/models.dart';
import '../../state/app_state.dart';
import '../l10n.dart';
import '../theme.dart';
import '../widgets/common.dart';
import 'scan_results_screen.dart';

class HistoryScreen extends StatelessWidget {
  const HistoryScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    return Scaffold(
      appBar: AppBar(title: Text(context.tr('Scan history', 'Historique des analyses'))),
      body: Responsive(
        child: state.reports.isEmpty
            ? EmptyState(Icons.history, context.tr('No scans yet', 'Aucune analyse'))
            : ListView.builder(
                padding: const EdgeInsets.all(16),
                itemCount: state.reports.length,
                itemBuilder: (_, i) {
                  final r = state.reports[i];
                  final worst = r.findings.where((f) => f.isActive).fold<Severity?>(null, (a, f) => a == null || f.severity.index > a.index ? f.severity : a);
                  return Card(
                    child: ListTile(
                      leading: Icon(r.background ? Icons.schedule : Icons.radar, color: worst == null ? SocColors.green : SocColors.severity(worst)),
                      title: Text(modeLabel(context, r.mode)),
                      subtitle: Text('${fmtDate(context, r.finishedAt)} · ${context.tr('${r.findings.length} finding(s)', '${r.findings.length} résultat(s)')}'),
                      trailing: worst == null ? null : SeverityPill(worst),
                      onTap: () => Navigator.push(context, MaterialPageRoute(builder: (_) => ScanResultsScreen(report: r))),
                    ),
                  );
                },
              ),
      ),
    );
  }
}
