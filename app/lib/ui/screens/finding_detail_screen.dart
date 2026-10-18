import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../core/models.dart';
import '../../state/app_state.dart';
import '../l10n.dart';
import '../theme.dart';
import '../widgets/common.dart';

class FindingDetailScreen extends StatelessWidget {
  const FindingDetailScreen({super.key, required this.finding});
  final Finding finding;

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final f = finding;
    return Scaffold(
      appBar: AppBar(title: Text(context.tr('Threat details', 'Détails de la menace'))),
      body: Responsive(
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            Text(context.lt(f.title), style: Theme.of(context).textTheme.titleLarge),
            const SizedBox(height: 8),
            Wrap(
              spacing: 6,
              runSpacing: 6,
              children: [
                SeverityPill(f.severity),
                ClassificationPill(f.classification),
                Pill(confidenceLabel(context, f.confidence), SocColors.muted),
                Pill(categoryLabel(context, f.category), SocColors.blue),
                Pill(remediationLabel(context, f.status), f.isActive ? SocColors.silver : SocColors.green),
              ],
            ),
            if (f.classification == Classification.suspicious || f.classification == Classification.unverified)
              InfoBanner(
                context.tr(
                  'This is an indicator, not a confirmed infection. Review the evidence and limitations before acting.',
                  'Ceci est un indicateur, pas une infection confirmée. Examinez les preuves et limites avant d’agir.',
                ),
              ),
            SectionTitle(context.tr('Description', 'Description')),
            Text(context.lt(f.description), style: const TextStyle(height: 1.4)),
            SectionTitle(context.tr('Evidence', 'Preuves')),
            Card(
              child: Column(
                children: [
                  for (final e in f.evidence.entries)
                    ListTile(
                      dense: true,
                      title: Text(e.key, style: const TextStyle(color: SocColors.muted)),
                      subtitle: SelectableText(e.value),
                    ),
                  if (f.evidence.isEmpty) ListTile(title: Text(context.tr('No additional evidence', 'Pas de preuve supplémentaire'))),
                ],
              ),
            ),
            SectionTitle(context.tr('Detection', 'Détection')),
            _kv(context.tr('Finding ID', 'ID du résultat'), f.id),
            _kv(context.tr('Rule', 'Règle'), '${f.ruleId} v${f.ruleVersion}'),
            _kv(context.tr('Method', 'Méthode'), context.lt(f.method)),
            _kv(context.tr('Detected', 'Détecté'), fmtDate(context, f.detectedAt)),
            _kv(context.tr('Platform', 'Plateforme'), f.platform.name),
            if (f.componentLabel != null || f.component != null) _kv(context.tr('Affected component', 'Composant concerné'), f.componentLabel ?? f.component!),
            _kv(context.tr('Known limitations', 'Limites connues'), context.lt(f.limitations)),
            SectionTitle(context.tr('Recommended remediation', 'Remédiation recommandée')),
            for (final step in f.remediation)
              Card(
                child: ListTile(
                  leading: Icon(step.action == null ? Icons.lightbulb_outline : Icons.open_in_new, color: SocColors.cyan),
                  title: Text(context.lt(step.label)),
                  onTap: step.action == null ? null : () => _perform(context, state, step),
                ),
              ),
            SectionTitle(context.tr('Status & feedback', 'Statut et retour')),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                OutlinedButton(
                  onPressed: () => state.setFindingStatus(f, RemediationStatus.inProgress),
                  child: Text(remediationLabel(context, RemediationStatus.inProgress)),
                ),
                OutlinedButton(
                  onPressed: () => state.setFindingStatus(f, RemediationStatus.resolved),
                  child: Text(context.tr('Mark resolved', 'Marquer résolu')),
                ),
                OutlinedButton(
                  onPressed: () => state.setFindingStatus(f, RemediationStatus.accepted),
                  child: Text(remediationLabel(context, RemediationStatus.accepted)),
                ),
                OutlinedButton.icon(
                  icon: const Icon(Icons.thumb_down_alt_outlined, size: 18),
                  onPressed: () => _falsePositive(context, state),
                  label: Text(context.tr('Report false positive', 'Signaler un faux positif')),
                ),
                if (!f.isActive) TextButton(onPressed: () => state.setFindingStatus(f, RemediationStatus.open), child: Text(context.tr('Reopen', 'Rouvrir'))),
              ],
            ),
            const SizedBox(height: 24),
          ],
        ),
      ),
    );
  }

  Widget _kv(String k, String v) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 4),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 130,
          child: Text(k, style: const TextStyle(color: SocColors.muted)),
        ),
        Expanded(child: SelectableText(v)),
      ],
    ),
  );

  Future<void> _perform(BuildContext context, AppState state, RemediationStep step) async {
    if (step.action == 'uninstall') {
      final ok = await showDialog<bool>(
        context: context,
        builder: (c) => AlertDialog(
          title: Text(c.tr('Uninstall ${finding.componentLabel ?? step.package}?', 'Désinstaller ${finding.componentLabel ?? step.package} ?')),
          content: Text(
            c.tr(
              'Android will show its own confirmation. If this may be stalkerware installed by someone with access to you, removing it can alert them — consider your safety first.',
              'Android affichera sa propre confirmation. S’il s’agit peut-être d’un stalkerware installé par un proche, sa suppression peut l’alerter — pensez d’abord à votre sécurité.',
            ),
          ),
          actions: [
            TextButton(onPressed: () => Navigator.pop(c, false), child: Text(c.tr('Cancel', 'Annuler'))),
            FilledButton(onPressed: () => Navigator.pop(c, true), child: Text(c.tr('Continue', 'Continuer'))),
          ],
        ),
      );
      if (ok != true) return;
    }
    final done = await state.perform(step);
    if (!done && context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            context.tr(
              'This system screen could not be opened on this device. Follow the step manually.',
              'Cet écran système n’a pas pu être ouvert. Suivez l’étape manuellement.',
            ),
          ),
        ),
      );
    }
  }

  Future<void> _falsePositive(BuildContext context, AppState state) async {
    final ctrl = TextEditingController();
    final ok = await showDialog<bool>(
      context: context,
      builder: (c) => AlertDialog(
        title: Text(c.tr('Report false positive', 'Signaler un faux positif')),
        content: TextField(
          controller: ctrl,
          maxLength: 300,
          decoration: InputDecoration(
            labelText: c.tr('Why is this expected? (optional, stays on device)', 'Pourquoi est-ce normal ? (optionnel, reste sur l’appareil)'),
          ),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(c, false), child: Text(c.tr('Cancel', 'Annuler'))),
          FilledButton(onPressed: () => Navigator.pop(c, true), child: Text(c.tr('Confirm', 'Confirmer'))),
        ],
      ),
    );
    if (ok == true) await state.markFalsePositive(finding, ctrl.text);
  }
}
