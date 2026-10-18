import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../state/app_state.dart';
import '../l10n.dart';
import '../theme.dart';
import '../widgets/common.dart';

class HelpScreen extends StatelessWidget {
  const HelpScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final items = <(String, String, String, String)>[
      ('How is the score calculated?', 'Comment le score est-il calculé ?',
          '100 minus a penalty per active finding: severity weight (low 2, medium 6, high 15, critical 30) × confidence (0.4 / 0.7 / 1.0) × classification (confirmed 1.5, suspicious & exposure 1.0, to-verify 0.5, info 0). Each category is capped at 45. Coverage is shown separately and never raises the score.',
          '100 moins une pénalité par résultat actif : poids de gravité (faible 2, moyen 6, élevé 15, critique 30) × confiance (0,4 / 0,7 / 1,0) × classification (confirmé 1,5, suspect et exposition 1,0, à vérifier 0,5, info 0). Chaque catégorie est plafonnée à 45. La couverture est affichée à part et n’augmente jamais le score.'),
      ('Why does Sentinel say “no conclusion”?', 'Pourquoi « aucune conclusion » ?',
          'Some threats (carrier interception, hidden root, zero-click spyware) are invisible to normal apps. Sentinel says so rather than guessing.',
          'Certaines menaces (interception opérateur, root masqué, logiciel espion zéro-clic) sont invisibles pour une app normale. Sentinel le dit au lieu de deviner.'),
      ('The daily scan did not run', 'L’analyse quotidienne ne s’est pas exécutée',
          'The OS decides when background work runs. On Android, exclude Sentinel from battery optimisation. On iOS, enable Background App Refresh and open the app regularly.',
          'L’OS décide de l’exécution en arrière-plan. Sur Android, excluez Sentinel de l’optimisation de batterie. Sur iOS, activez l’Actualisation en arrière-plan et ouvrez l’app régulièrement.'),
      ('A legitimate app is flagged', 'Une app légitime est signalée',
          'Open the finding and tap “Report false positive”. It stays dismissed in future scans. Heuristics flag capabilities, not intent.',
          'Ouvrez le résultat et touchez « Signaler un faux positif ». Il restera ignoré. Les heuristiques signalent des capacités, pas des intentions.'),
      ('I think someone is spying on me', 'Je pense être espionné(e)',
          'Your safety comes first. Removing stalkerware may alert the person who installed it. Contact a support organisation (e.g. stopstalkerware.org, in France 3919) and consider a forensic check (Amnesty Tech MVT, Access Now Helpline).',
          'Votre sécurité d’abord. Supprimer un stalkerware peut alerter la personne qui l’a installé. Contactez une association (ex. stopstalkerware.org, en France le 3919) et envisagez une expertise (MVT d’Amnesty Tech, Access Now Helpline).'),
      ('Why are some checks unavailable on iOS?', 'Pourquoi certaines vérifications manquent sur iOS ?',
          'iOS sandboxing prevents any App Store app from listing other apps, reading profiles or seeing other apps’ microphone use. Use the native tools listed in reports.',
          'Le bac à sable d’iOS empêche toute app de lister les autres apps, lire les profils ou voir l’usage du micro. Utilisez les outils natifs indiqués dans les rapports.'),
    ];
    return Scaffold(
      appBar: AppBar(title: Text(context.tr('Help & troubleshooting', 'Aide et dépannage'))),
      body: Responsive(
        child: ListView(padding: const EdgeInsets.all(16), children: [
          for (final (qEn, qFr, aEn, aFr) in items)
            Card(child: ExpansionTile(title: Text(context.tr(qEn, qFr)), childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 16), children: [Text(context.tr(aEn, aFr), style: const TextStyle(height: 1.4))])),
        ]),
      ),
    );
  }
}

class AboutScreen extends StatelessWidget {
  const AboutScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    return Scaffold(
      appBar: AppBar(title: Text(context.tr('About & legal', 'À propos et mentions légales'))),
      body: Responsive(
        child: ListView(padding: const EdgeInsets.all(16), children: [
          Center(child: Text(state.settings.brandName, style: Theme.of(context).textTheme.headlineSmall)),
          Center(child: Text('v0.1.0 · rule pack v${state.pack.version}', style: const TextStyle(color: SocColors.muted))),
          const SizedBox(height: 16),
          InfoBanner(context.tr(
              'Sentinel provides security indicators and guidance. It cannot detect every threat and does not guarantee that a device is free of malware or surveillance. Heuristic results are not proof of compromise.',
              'Sentinel fournit des indicateurs et des conseils de sécurité. Il ne peut pas détecter toutes les menaces et ne garantit pas l’absence de malware ou de surveillance. Les résultats heuristiques ne prouvent pas une compromission.'),
              color: SocColors.amber, icon: Icons.gavel),
          ListTile(title: Text(context.tr('Device', 'Appareil')), subtitle: Text('${state.platformInfo['manufacturer'] ?? ''} ${state.platformInfo['model'] ?? ''} · ${state.platformInfo['osVersion'] ?? ''}')),
          ListTile(title: Text(context.tr('Data sources', 'Sources de données')),
              subtitle: Text(context.tr('Bundled test indicators (CC0), EICAR test string, Google Safe Browsing test URLs. Backend feeds keep their own attribution.',
                  'Indicateurs de test intégrés (CC0), chaîne EICAR, URL de test Google Safe Browsing. Les flux du serveur conservent leur attribution.'))),
          ListTile(
            title: Text(context.tr('Open-source licences', 'Licences open source')),
            onTap: () => showLicensePage(context: context, applicationName: state.settings.brandName, applicationVersion: '0.1.0'),
          ),
        ]),
      ),
    );
  }
}
