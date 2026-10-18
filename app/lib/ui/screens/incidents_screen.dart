import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:share_plus/share_plus.dart';

import '../../core/incident.dart';
import '../../state/app_state.dart';
import '../l10n.dart';
import '../theme.dart';
import '../widgets/common.dart';
import 'finding_detail_screen.dart';

String incidentStatusLabel(BuildContext c, IncidentStatus s) => switch (s) {
      IncidentStatus.newIncident => c.tr('New', 'Nouveau'),
      IncidentStatus.investigating => c.tr('Investigating', 'En investigation'),
      IncidentStatus.confirmed => c.tr('Confirmed', 'Confirmé'),
      IncidentStatus.falsePositive => c.tr('False positive', 'Faux positif'),
      IncidentStatus.remediationRecommended => c.tr('Remediation recommended', 'Remédiation recommandée'),
      IncidentStatus.resolved => c.tr('Resolved', 'Résolu'),
    };

class IncidentsScreen extends StatefulWidget {
  const IncidentsScreen({super.key});
  @override
  State<IncidentsScreen> createState() => _IncidentsScreenState();
}

class _IncidentsScreenState extends State<IncidentsScreen> {
  bool _showClosed = false;

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final list = state.incidents.values.where((i) => _showClosed || i.open).toList()
      ..sort((a, b) {
        final s = b.finding.severity.index.compareTo(a.finding.severity.index);
        return s != 0 ? s : b.lastObserved.compareTo(a.lastObserved);
      });
    return Scaffold(
      appBar: AppBar(title: Text(context.tr('Incident management', 'Gestion des incidents')), actions: [
        FilterChip(
          label: Text(context.tr('Show closed', 'Afficher fermés')),
          selected: _showClosed,
          onSelected: (v) => setState(() => _showClosed = v),
        ),
        const SizedBox(width: 8),
      ]),
      body: Responsive(
        child: list.isEmpty
            ? EmptyState(Icons.task_alt, context.tr('No open incidents. Medium-or-higher findings become incidents automatically.',
                'Aucun incident ouvert. Les résultats de gravité moyenne ou plus deviennent des incidents.'))
            : ListView.builder(
                padding: const EdgeInsets.all(16),
                itemCount: list.length,
                itemBuilder: (_, i) {
                  final inc = list[i];
                  return Card(
                    child: ListTile(
                      leading: Icon(Icons.report, color: SocColors.severity(inc.finding.severity)),
                      title: Text(context.lt(inc.finding.title)),
                      subtitle: Text('${inc.id} · ${incidentStatusLabel(context, inc.status)} · ${ago(context, inc.lastObserved)}'),
                      trailing: SeverityPill(inc.finding.severity),
                      onTap: () => Navigator.push(context, MaterialPageRoute(builder: (_) => IncidentDetailScreen(incident: inc))),
                    ),
                  );
                },
              ),
      ),
    );
  }
}

class IncidentDetailScreen extends StatefulWidget {
  const IncidentDetailScreen({super.key, required this.incident});
  final Incident incident;
  @override
  State<IncidentDetailScreen> createState() => _IncidentDetailScreenState();
}

class _IncidentDetailScreenState extends State<IncidentDetailScreen> {
  late final _notes = TextEditingController(text: widget.incident.notes);

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final inc = widget.incident;
    final f = inc.finding;
    return Scaffold(
      appBar: AppBar(title: Text(inc.id), actions: [
        IconButton(
          tooltip: context.tr('Export report', 'Exporter le rapport'),
          icon: const Icon(Icons.ios_share),
          onPressed: () => SharePlus.instance.share(ShareParams(text: IncidentManager.exportMarkdown(inc, context.lang), subject: inc.id)),
        ),
      ]),
      body: Responsive(
        child: ListView(padding: const EdgeInsets.all(16), children: [
          Text(context.lt(f.title), style: Theme.of(context).textTheme.titleLarge),
          const SizedBox(height: 8),
          Wrap(spacing: 6, runSpacing: 6, children: [
            SeverityPill(f.severity),
            ClassificationPill(f.classification),
            Pill(confidenceLabel(context, f.confidence), SocColors.muted),
          ]),
          const SizedBox(height: 12),
          Text('${context.tr('First observed', 'Première observation')}: ${fmtDate(context, inc.firstObserved)}'),
          Text('${context.tr('Last observed', 'Dernière observation')}: ${fmtDate(context, inc.lastObserved)}'),
          Text('${context.tr('Detection source', 'Source de détection')}: ${f.ruleId} — ${context.lt(f.method)}'),
          if (f.componentLabel != null) Text('${context.tr('Affected component', 'Composant')}: ${f.componentLabel}'),
          SectionTitle(context.tr('Status', 'Statut')),
          DropdownButtonFormField<IncidentStatus>(
            initialValue: inc.status,
            items: [for (final s in IncidentStatus.values) DropdownMenuItem(value: s, child: Text(incidentStatusLabel(context, s)))],
            onChanged: (s) async {
              if (s == null) return;
              if (s == IncidentStatus.resolved || s == IncidentStatus.falsePositive) {
                final ok = await showDialog<bool>(
                  context: context,
                  builder: (c) => AlertDialog(
                    title: Text(c.tr('Close this incident?', 'Fermer cet incident ?')),
                    content: Text(c.tr('It will reopen automatically if a later scan observes it again (except false positives).',
                        'Il sera rouvert si une analyse ultérieure l’observe de nouveau (sauf faux positifs).')),
                    actions: [
                      TextButton(onPressed: () => Navigator.pop(c, false), child: Text(c.tr('Cancel', 'Annuler'))),
                      FilledButton(onPressed: () => Navigator.pop(c, true), child: Text(c.tr('Confirm', 'Confirmer'))),
                    ],
                  ),
                );
                if (ok != true) return;
              }
              await state.setIncidentStatus(inc, s, notes: _notes.text);
            },
          ),
          SectionTitle(context.tr('Containment & remediation', 'Confinement et remédiation')),
          for (final r in f.remediation) ListTile(leading: const Icon(Icons.arrow_right), title: Text(context.lt(r.label))),
          TextButton(
            onPressed: () => Navigator.push(context, MaterialPageRoute(builder: (_) => FindingDetailScreen(finding: f))),
            child: Text(context.tr('Open evidence and actions', 'Ouvrir preuves et actions')),
          ),
          SectionTitle(context.tr('Timeline', 'Chronologie')),
          for (final t in inc.timeline.reversed)
            ListTile(dense: true, leading: const Icon(Icons.circle, size: 10, color: SocColors.cyan), title: Text(context.lt(t.text)), subtitle: Text(fmtDate(context, t.at))),
          SectionTitle(context.tr('Resolution notes', 'Notes de résolution')),
          TextField(controller: _notes, maxLines: 4, maxLength: 2000, decoration: const InputDecoration(border: OutlineInputBorder())),
          Align(
            alignment: Alignment.centerRight,
            child: FilledButton(
              onPressed: () async {
                inc.notes = _notes.text;
                await state.repo.saveIncidents(state.incidents);
                if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(context.tr('Saved', 'Enregistré'))));
              },
              child: Text(context.tr('Save notes', 'Enregistrer')),
            ),
          ),
        ]),
      ),
    );
  }
}
