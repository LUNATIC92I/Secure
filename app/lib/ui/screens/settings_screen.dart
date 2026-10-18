import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../detection/android_rules.dart';
import '../../detection/common_rules.dart';
import '../../state/app_state.dart';
import '../l10n.dart';
import '../theme.dart';
import '../widgets/common.dart';
import 'help_screen.dart';
import 'onboarding_screen.dart';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    void go(Widget w) => Navigator.push(context, MaterialPageRoute(builder: (_) => w));
    return Scaffold(
      appBar: AppBar(title: Text(context.tr('Settings', 'Réglages'))),
      body: Responsive(
        child: ListView(padding: const EdgeInsets.all(16), children: [
          SectionTitle(context.tr('General', 'Général')),
          ListTile(
            leading: const Icon(Icons.language),
            title: Text(context.tr('Language', 'Langue')),
            trailing: DropdownButton<String?>(
              value: state.settings.languageCode,
              items: [
                DropdownMenuItem(value: null, child: Text(context.tr('System', 'Système'))),
                const DropdownMenuItem(value: 'en', child: Text('English')),
                const DropdownMenuItem(value: 'fr', child: Text('Français')),
              ],
              onChanged: (v) => state.updateSettings((s) => s.languageCode = v),
            ),
          ),
          ListTile(
            leading: const Icon(Icons.badge_outlined),
            title: Text(context.tr('Product name', 'Nom du produit')),
            subtitle: Text(state.settings.brandName),
            onTap: () async {
              final c = TextEditingController(text: state.settings.brandName);
              final v = await showDialog<String>(
                context: context,
                builder: (d) => AlertDialog(
                  title: Text(d.tr('Product name', 'Nom du produit')),
                  content: TextField(controller: c, maxLength: 40),
                  actions: [FilledButton(onPressed: () => Navigator.pop(d, c.text.trim()), child: const Text('OK'))],
                ),
              );
              if (v != null && v.isNotEmpty) await state.updateSettings((s) => s.brandName = v);
            },
          ),
          SectionTitle(context.tr('Protection', 'Protection')),
          ListTile(leading: const Icon(Icons.notifications_outlined), title: Text(context.tr('Notifications', 'Notifications')), onTap: () => go(const NotificationSettingsScreen())),
          ListTile(leading: const Icon(Icons.hub_outlined), title: Text(context.tr('Threat intelligence & rules', 'Renseignement et règles')), onTap: () => go(const IntelSettingsScreen())),
          ListTile(leading: const Icon(Icons.privacy_tip_outlined), title: Text(context.tr('Privacy controls', 'Contrôles de confidentialité')), onTap: () => go(const PrivacyScreen())),
          SectionTitle(context.tr('Support', 'Assistance')),
          ListTile(leading: const Icon(Icons.grid_on), title: Text(context.tr('Platform capability matrix', 'Matrice des capacités')),
              onTap: () => go(Scaffold(appBar: AppBar(), body: CapabilityMatrix(platform: state.platform)))),
          ListTile(leading: const Icon(Icons.help_outline), title: Text(context.tr('Help & troubleshooting', 'Aide et dépannage')), onTap: () => go(const HelpScreen())),
          ListTile(leading: const Icon(Icons.info_outline), title: Text(context.tr('About & legal', 'À propos et mentions légales')), onTap: () => go(const AboutScreen())),
        ]),
      ),
    );
  }
}

class NotificationSettingsScreen extends StatelessWidget {
  const NotificationSettingsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    return Scaffold(
      appBar: AppBar(title: Text(context.tr('Notifications', 'Notifications'))),
      body: Responsive(
        child: ListView(padding: const EdgeInsets.all(16), children: [
          SwitchListTile(
            value: state.settings.notificationsEnabled,
            title: Text(context.tr('Security alerts', 'Alertes de sécurité')),
            subtitle: Text(context.tr('Grouped, and never repeated for an unchanged finding.', 'Regroupées et jamais répétées pour un résultat inchangé.')),
            onChanged: (v) async {
              if (v) {
                final granted = await state.notifier.requestPermission();
                if (!granted && context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(context.tr('Notification permission denied.', 'Autorisation refusée.'))));
                  return;
                }
              }
              await state.updateSettings((s) => s.notificationsEnabled = v);
            },
          ),
          SwitchListTile(
            value: state.settings.notifyHighOnly,
            title: Text(context.tr('Only high and critical findings', 'Uniquement les résultats élevés et critiques')),
            subtitle: Text(context.tr('Off: medium findings are notified too.', 'Désactivé : les résultats moyens sont aussi notifiés.')),
            onChanged: state.settings.notificationsEnabled ? (v) => state.updateSettings((s) => s.notifyHighOnly = v) : null,
          ),
          SwitchListTile(
            value: state.settings.dailyAssessment,
            title: Text(context.tr('Daily assessment', 'Évaluation quotidienne')),
            subtitle: Text(context.tr('If the OS cannot run it, the dashboard shows an “overdue” warning; it never pretends a scan ran.',
                'Si l’OS ne peut pas l’exécuter, le tableau de bord affiche « en retard » ; il ne prétend jamais qu’une analyse a eu lieu.')),
            onChanged: (v) => state.updateSettings((s) => s.dailyAssessment = v),
          ),
          if (state.settings.notificationsEnabled)
            TextButton(
              onPressed: () => state.notifier.notifyText(2001, 'Sentinel', context.tr('Test notification', 'Notification de test')),
              child: Text(context.tr('Send test notification', 'Envoyer une notification de test')),
            ),
        ]),
      ),
    );
  }
}

class IntelSettingsScreen extends StatefulWidget {
  const IntelSettingsScreen({super.key});
  @override
  State<IntelSettingsScreen> createState() => _IntelSettingsScreenState();
}

class _IntelSettingsScreenState extends State<IntelSettingsScreen> {
  late final AppState state = context.read<AppState>();
  late final _url = TextEditingController(text: state.settings.backendUrl);
  late final _token = TextEditingController(text: state.settings.backendToken);
  String? _updateResult;

  @override
  Widget build(BuildContext context) {
    final s = context.watch<AppState>();
    final rules = [...androidRules, ...commonRules].where((r) => r.platforms.contains(s.platform)).toList();
    return Scaffold(
      appBar: AppBar(title: Text(context.tr('Threat intelligence', 'Renseignement sur les menaces'))),
      body: Responsive(
        child: ListView(padding: const EdgeInsets.all(16), children: [
          SectionTitle(context.tr('Local rule pack', 'Pack de règles local')),
          Card(
            child: Column(children: [
              ListTile(title: Text(context.tr('Version', 'Version')), trailing: Text('v${s.pack.version} (${s.pack.source})')),
              ListTile(title: Text(context.tr('Signature', 'Signature')), trailing: Text(s.pack.verified ? context.tr('Verified (Ed25519)', 'Vérifiée (Ed25519)') : context.tr('Not verified', 'Non vérifiée'))),
              ListTile(title: Text(context.tr('Indicators', 'Indicateurs')), trailing: Text('${s.pack.indicators.length} (${s.pack.indicators.where((i) => i.test).length} test)')),
              ListTile(title: Text(context.tr('YARA-lite rules', 'Règles YARA-lite')), trailing: Text('${s.pack.yaraRules.length}')),
              ListTile(title: Text(context.tr('Issued', 'Émis le')), trailing: Text(fmtDate(context, s.pack.issuedAt))),
            ]),
          ),
          if (s.pack.indicators.every((i) => i.test))
            InfoBanner(context.tr('The bundled pack only contains test indicators. Connect a backend to load real feeds (URLhaus, stalkerware indicators).',
                'Le pack intégré ne contient que des indicateurs de test. Connectez un serveur pour charger de vrais flux (URLhaus, indicateurs stalkerware).'),
                color: SocColors.amber, icon: Icons.warning_amber_rounded),
          SectionTitle(context.tr('Optional backend', 'Serveur optionnel')),
          TextField(controller: _url, decoration: InputDecoration(labelText: context.tr('Backend URL (https://…)', 'URL du serveur (https://…)'), border: const OutlineInputBorder())),
          const SizedBox(height: 8),
          TextField(controller: _token, obscureText: true, decoration: InputDecoration(labelText: context.tr('Device token', 'Jeton de l’appareil'), border: const OutlineInputBorder())),
          Row(children: [
            FilledButton(
              onPressed: () async {
                final u = Uri.tryParse(_url.text.trim());
                if (_url.text.trim().isNotEmpty && (u == null || (u.scheme != 'https' && u.host != '10.0.2.2'))) {
                  setState(() => _updateResult = context.tr('HTTPS is required.', 'HTTPS est obligatoire.'));
                  return;
                }
                await s.updateSettings((x) {
                  x.backendUrl = _url.text.trim();
                  x.backendToken = _token.text.trim();
                });
                setState(() => _updateResult = context.tr('Saved', 'Enregistré'));
              },
              child: Text(context.tr('Save', 'Enregistrer')),
            ),
            const SizedBox(width: 8),
            OutlinedButton(
              onPressed: s.settings.backendConfigured
                  ? () async {
                      final r = await s.updateRulePack();
                      setState(() => _updateResult = r == 'ok' ? context.tr('Rule pack updated to v${s.pack.version}', 'Pack mis à jour en v${s.pack.version}') : r);
                    }
                  : null,
              child: Text(context.tr('Update rules', 'Mettre à jour')),
            ),
          ]),
          if (_updateResult != null) Padding(padding: const EdgeInsets.only(top: 8), child: Text(_updateResult!)),
          SwitchListTile(
            value: s.settings.cloudIntel,
            title: Text(context.tr('Cloud reputation checks', 'Réputation cloud')),
            subtitle: Text(context.tr('Sends SHA-256 hashes of files and domains to your backend, which may query Google Web Risk / VirusTotal. Never files, contacts or messages.',
                'Envoie des empreintes SHA-256 de fichiers et domaines à votre serveur, qui peut interroger Google Web Risk / VirusTotal. Jamais de fichiers, contacts ou messages.')),
            onChanged: s.settings.backendConfigured ? (v) => s.updateSettings((x) => x.cloudIntel = v) : null,
          ),
          SwitchListTile(
            value: s.settings.cloudFullUrls,
            title: Text(context.tr('Send full URLs for detailed analysis', 'Envoyer les URL complètes')),
            subtitle: Text(context.tr('URLs can contain personal tokens. Off by default.', 'Les URL peuvent contenir des jetons personnels. Désactivé par défaut.')),
            onChanged: s.settings.cloudIntel ? (v) => s.updateSettings((x) => x.cloudFullUrls = v) : null,
          ),
          SectionTitle(context.tr('Provider health', 'État des fournisseurs')),
          for (final p in s.intel.providers)
            ListTile(
              dense: true,
              leading: Icon(p.isRemote ? Icons.cloud_outlined : Icons.phone_android),
              title: Text(p.name),
              subtitle: Text(() {
                final h = s.intel.health[p.id];
                if (h == null) return context.tr('Not used yet', 'Pas encore utilisé');
                return '${h.degraded ? context.tr('Degraded', 'Dégradé') : 'OK'} · ${h.lastError ?? ''}';
              }()),
            ),
          SectionTitle(context.tr('Detection rules (${rules.length})', 'Règles de détection (${rules.length})')),
          for (final r in rules)
            ExpansionTile(
              tilePadding: EdgeInsets.zero,
              title: Text('${r.id} · ${context.lt(r.name)}'),
              subtitle: Text('v${r.version}', style: const TextStyle(color: SocColors.muted)),
              children: [
                ListTile(dense: true, title: Text(context.lt(r.description))),
                ListTile(dense: true, title: Text(context.tr('Confidence model', 'Modèle de confiance')), subtitle: Text(context.lt(r.confidenceModel))),
                ListTile(dense: true, title: Text(context.tr('Known false positives', 'Faux positifs connus')), subtitle: Text(context.lt(r.knownFalsePositives))),
              ],
            ),
          for (final y in s.pack.yaraRules)
            ListTile(dense: true, leading: const Icon(Icons.code), title: Text('YARA · ${y.name}'), subtitle: Text(y.meta['description'] ?? '')),
        ]),
      ),
    );
  }
}

class PrivacyScreen extends StatelessWidget {
  const PrivacyScreen({super.key});

  Future<bool> _confirm(BuildContext context, String title, String body) async =>
      await showDialog<bool>(
        context: context,
        builder: (c) => AlertDialog(
          title: Text(title),
          content: Text(body),
          actions: [
            TextButton(onPressed: () => Navigator.pop(c, false), child: Text(c.tr('Cancel', 'Annuler'))),
            FilledButton(style: FilledButton.styleFrom(backgroundColor: SocColors.red), onPressed: () => Navigator.pop(c, true), child: Text(c.tr('Delete', 'Supprimer'))),
          ],
        ),
      ) ==
      true;

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    return Scaffold(
      appBar: AppBar(title: Text(context.tr('Privacy controls', 'Contrôles de confidentialité'))),
      body: Responsive(
        child: ListView(padding: const EdgeInsets.all(16), children: [
          InfoBanner(context.tr(
              'All results are stored only on this device, encrypted with AES-256-GCM using a key in the Android Keystore / iOS Keychain, and excluded from cloud backups.',
              'Tous les résultats restent sur l’appareil, chiffrés en AES-256-GCM avec une clé du Keystore Android / Trousseau iOS, et exclus des sauvegardes cloud.')),
          ListTile(
            title: Text(context.tr('Keep history for', 'Conserver l’historique')),
            trailing: DropdownButton<int>(
              value: state.settings.retentionDays,
              items: [for (final d in [7, 30, 90, 365]) DropdownMenuItem(value: d, child: Text(context.tr('$d days', '$d jours')))],
              onChanged: (v) => state.updateSettings((s) => s.retentionDays = v ?? 90),
            ),
          ),
          SwitchListTile(
            value: state.settings.networkChecks,
            title: Text(context.tr('Network integrity checks in comprehensive scans', 'Vérifications réseau dans l’analyse complète')),
            subtitle: Text(context.tr('Opens TLS connections to google.com, cloudflare.com, apple.com.', 'Ouvre des connexions TLS vers google.com, cloudflare.com, apple.com.')),
            onChanged: (v) => state.updateSettings((s) => s.networkChecks = v),
          ),
          const Divider(),
          ListTile(
            leading: const Icon(Icons.history_toggle_off, color: SocColors.amber),
            title: Text(context.tr('Delete scan history & incidents', 'Supprimer l’historique et les incidents')),
            onTap: () async {
              if (await _confirm(context, context.tr('Delete history?', 'Supprimer l’historique ?'),
                  context.tr('Scan reports, incidents and tracker sightings will be erased.', 'Rapports, incidents et observations de traceurs seront effacés.'))) {
                await state.deleteHistory();
              }
            },
          ),
          ListTile(
            leading: const Icon(Icons.delete_forever, color: SocColors.red),
            title: Text(context.tr('Erase all data and keys', 'Effacer toutes les données et clés')),
            subtitle: Text(context.tr('Resets the app to first launch.', 'Réinitialise l’app.')),
            onTap: () async {
              if (await _confirm(context, context.tr('Erase everything?', 'Tout effacer ?'),
                  context.tr('All data, settings and the encryption key will be destroyed. This cannot be undone.', 'Données, réglages et clé de chiffrement seront détruits. Irréversible.'))) {
                await state.wipeAll();
              }
            },
          ),
          SectionTitle(context.tr('What Sentinel never collects', 'Ce que Sentinel ne collecte jamais')),
          Text(context.tr('Call contents, SMS, contacts, passwords, microphone audio, location history. No advertising or analytics SDK.',
              'Contenu des appels, SMS, contacts, mots de passe, audio du micro, historique de localisation. Aucun SDK publicitaire ou analytique.')),
        ]),
      ),
    );
  }
}
