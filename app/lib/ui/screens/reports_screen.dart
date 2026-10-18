import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:share_plus/share_plus.dart';

import '../../core/models.dart';
import '../../state/app_state.dart';
import '../l10n.dart';
import '../widgets/common.dart';

/// Builds the user-exportable posture report (Markdown). Contains only what the app displays.
String buildPostureReport(AppState s, String lang) {
  String t(String en, String fr) => lang == 'fr' ? fr : en;
  final r = s.lastFullReport;
  final score = s.score;
  final b = StringBuffer()
    ..writeln('# ${s.settings.brandName} — ${t('Security posture report', 'Rapport de posture de sécurité')}')
    ..writeln()
    ..writeln('${t('Generated', 'Généré')}: ${DateTime.now().toIso8601String()}  ')
    ..writeln('${t('Device', 'Appareil')}: ${s.platformInfo['manufacturer'] ?? ''} ${s.platformInfo['model'] ?? ''} (${s.platform.name} ${s.platformInfo['osVersion'] ?? ''})  ')
    ..writeln('${t('Rule pack', 'Pack de règles')}: v${s.pack.version}${s.pack.verified ? ' (signature verified)' : ''}');
  if (r == null || score == null) {
    b.writeln('\n${t('No scan has been completed yet.', 'Aucune analyse terminée.')}');
    return b.toString();
  }
  b
    ..writeln()
    ..writeln('## ${t('Summary', 'Résumé')}')
    ..writeln('- ${t('Score', 'Score')}: **${score.score}/100** (${score.posture.name})')
    ..writeln('- ${t('Coverage', 'Couverture')}: ${(score.coverage * 100).round()}%')
    ..writeln('- ${t('Last scan', 'Dernière analyse')}: ${r.mode.name}, ${r.finishedAt.toIso8601String()}${r.background ? ' (background)' : ''}')
    ..writeln('- ${t('Open incidents', 'Incidents ouverts')}: ${s.incidents.values.where((i) => i.open).length}')
    ..writeln()
    ..writeln('## ${t('Findings', 'Résultats')}');
  for (final f in r.findings) {
    b.writeln('- [${f.severity.name.toUpperCase()} · ${f.classification.name} · ${f.confidence.name}] ${f.title.of(lang)} (${f.ruleId}${f.isActive ? '' : ', ${f.status.name}'})');
  }
  if (r.findings.isEmpty) b.writeln(t('- None in checked areas.', '- Aucun dans les zones vérifiées.'));
  b
    ..writeln()
    ..writeln('## ${t('Not checked', 'Non vérifié')}');
  for (final c in r.coverage.where((c) => c.status != CoverageStatus.checked)) {
    b.writeln('- ${c.label.of(lang)}${c.note == null ? '' : ': ${c.note!.of(lang)}'}');
  }
  b
    ..writeln()
    ..writeln(t('_A clean report is not a guarantee that the device is free of malware or surveillance._',
        '_Un rapport propre ne garantit pas l’absence de malware ou de surveillance._'));
  return b.toString();
}

class ReportsScreen extends StatelessWidget {
  const ReportsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final md = buildPostureReport(state, context.lang);
    return Scaffold(
      appBar: AppBar(title: Text(context.tr('Security report', 'Rapport de sécurité')), actions: [
        IconButton(
          tooltip: context.tr('Share / export', 'Partager / exporter'),
          icon: const Icon(Icons.ios_share),
          onPressed: () => SharePlus.instance.share(ShareParams(text: md, subject: 'Sentinel report')),
        ),
      ]),
      body: Responsive(
        child: ListView(padding: const EdgeInsets.all(16), children: [
          InfoBanner(context.tr('Exporting is your choice: the report leaves the device only through the share sheet.',
              'L’export est votre choix : le rapport ne quitte l’appareil que via le menu de partage.')),
          Card(child: Padding(padding: const EdgeInsets.all(16), child: SelectableText(md, style: const TextStyle(fontFamily: 'monospace', fontSize: 12.5)))),
        ]),
      ),
    );
  }
}
