import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../core/snapshot.dart';
import '../../detection/android_rules.dart';
import '../../detection/permissions.dart';
import '../../state/app_state.dart';
import '../l10n.dart';
import '../theme.dart';
import '../widgets/common.dart';

class AppsScreen extends StatefulWidget {
  const AppsScreen({super.key});
  @override
  State<AppsScreen> createState() => _AppsScreenState();
}

class _AppsScreenState extends State<AppsScreen> {
  late Future<List<AppInfo>> _future = context.read<AppState>().loadApps();
  bool _includeSystem = false;
  String _query = '';

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: Text(context.tr('Application risk', 'Risque des applications')), actions: [
          IconButton(icon: const Icon(Icons.refresh), tooltip: context.tr('Reload', 'Recharger'), onPressed: () => setState(() => _future = context.read<AppState>().loadApps())),
        ]),
        body: Responsive(
          child: FutureBuilder<List<AppInfo>>(
            future: _future,
            builder: (context, snap) {
              if (snap.hasError) return EmptyState(Icons.error_outline, '${snap.error}');
              if (!snap.hasData) return const Center(child: CircularProgressIndicator());
              final apps = snap.data!
                  .where((a) => _includeSystem || !a.isSystem)
                  .where((a) => _query.isEmpty || a.label.toLowerCase().contains(_query) || a.package.contains(_query))
                  .toList()
                ..sort((a, b) => appRiskScore(b).compareTo(appRiskScore(a)));
              return ListView(padding: const EdgeInsets.all(16), children: [
                InfoBanner(context.tr(
                    'Apps are ranked by capability, not proven behaviour. A high score means “review this”, not “malicious”.',
                    'Les apps sont classées selon leurs capacités, pas un comportement prouvé. Un score élevé signifie « à examiner », pas « malveillant ».')),
                TextField(
                  decoration: InputDecoration(prefixIcon: const Icon(Icons.search), hintText: context.tr('Search apps', 'Rechercher'), border: const OutlineInputBorder()),
                  onChanged: (v) => setState(() => _query = v.toLowerCase()),
                ),
                SwitchListTile(
                  contentPadding: EdgeInsets.zero,
                  value: _includeSystem,
                  onChanged: (v) => setState(() => _includeSystem = v),
                  title: Text(context.tr('Include system apps', 'Inclure les apps système')),
                ),
                Text(context.tr('${apps.length} apps', '${apps.length} apps'), style: const TextStyle(color: SocColors.muted)),
                for (final a in apps) _tile(context, a),
              ]);
            },
          ),
        ),
      );

  Widget _tile(BuildContext context, AppInfo a) {
    final score = appRiskScore(a);
    final color = score >= 9 ? SocColors.red : (score >= 5 ? SocColors.amber : SocColors.green);
    return Card(
      child: ListTile(
        leading: CircleAvatar(backgroundColor: color.withValues(alpha: 0.2), child: Text('$score', style: TextStyle(color: color, fontWeight: FontWeight.w800))),
        title: Text(a.label),
        subtitle: Text([
          a.package,
          if (a.isSideloaded) context.tr('outside store', 'hors store'),
          if (!a.hasLauncher && !a.isSystem) context.tr('no icon', 'sans icône'),
        ].join(' · ')),
        onTap: () => Navigator.push(context, MaterialPageRoute(builder: (_) => AppDetailScreen(app: a))),
      ),
    );
  }
}

class AppDetailScreen extends StatelessWidget {
  const AppDetailScreen({super.key, required this.app});
  final AppInfo app;

  @override
  Widget build(BuildContext context) {
    final state = context.read<AppState>();
    final sensitive = app.grantedPermissions.map((p) => sensitiveByName[p]).nonNulls.toList();
    final others = app.grantedPermissions.where((p) => !sensitiveByName.containsKey(p)).toList()..sort();
    return Scaffold(
      appBar: AppBar(title: Text(app.label)),
      body: Responsive(
        child: ListView(padding: const EdgeInsets.all(16), children: [
          Text(app.package, style: const TextStyle(color: SocColors.muted)),
          const SizedBox(height: 8),
          Wrap(spacing: 6, runSpacing: 6, children: [
            Pill('${context.tr('Risk score', 'Score de risque')} ${appRiskScore(app)}', SocColors.blue),
            if (app.isSystem) Pill(context.tr('System app', 'App système'), SocColors.muted),
            if (app.isSideloaded) Pill(context.tr('Installed outside a store', 'Installée hors store'), SocColors.amber),
            if (!app.hasLauncher && !app.isSystem) Pill(context.tr('No launcher icon', 'Pas d’icône'), SocColors.amber),
            if (app.isAccessibilityProvider) Pill(context.tr('Provides accessibility service', 'Fournit un service d’accessibilité'), SocColors.purple),
            if (app.isDeviceAdminProvider) Pill(context.tr('Can be device admin', 'Peut être administrateur'), SocColors.purple),
            if (app.debuggable) Pill(context.tr('Debuggable', 'Débogable'), SocColors.cyan),
          ]),
          SectionTitle(context.tr('Details', 'Détails')),
          ListTile(dense: true, title: Text(context.tr('Version', 'Version')), subtitle: Text(app.versionName ?? '-')),
          ListTile(dense: true, title: Text(context.tr('Installed by', 'Installée par')), subtitle: Text(app.installer ?? context.tr('Unknown / manual install', 'Inconnu / installation manuelle'))),
          if (app.firstInstall != null) ListTile(dense: true, title: Text(context.tr('First installed', 'Installée le')), subtitle: Text(fmtDate(context, app.firstInstall!))),
          ListTile(dense: true, title: Text(context.tr('Target SDK', 'SDK cible')), subtitle: Text('${app.targetSdk ?? '-'}')),
          ListTile(dense: true, title: Text(context.tr('Signing certificate SHA-256', 'Certificat de signature SHA-256')), subtitle: SelectableText(app.signingSha256.join('\n'))),
          SectionTitle(context.tr('Sensitive permissions granted', 'Autorisations sensibles accordées')),
          if (sensitive.isEmpty) Text(context.tr('None', 'Aucune')),
          for (final p in sensitive)
            ListTile(dense: true, leading: const Icon(Icons.warning_amber, color: SocColors.amber), title: Text(p.name.split('.').last), subtitle: Text(context.lt(p.why))),
          ExpansionTile(
            tilePadding: EdgeInsets.zero,
            title: Text(context.tr('Other granted permissions (${others.length})', 'Autres autorisations (${others.length})')),
            children: [for (final p in others) ListTile(dense: true, title: Text(p))],
          ),
          const SizedBox(height: 12),
          FilledButton.icon(
            onPressed: () => state.native.openSettings('appDetails', package: app.package),
            icon: const Icon(Icons.settings),
            label: Text(context.tr('Review permissions in system settings', 'Revoir les autorisations dans les réglages')),
          ),
          if (!app.isSystem)
            OutlinedButton.icon(
              onPressed: () => state.native.requestUninstall(app.package),
              icon: const Icon(Icons.delete_outline),
              label: Text(context.tr('Uninstall (system confirmation)', 'Désinstaller (confirmation système)')),
            ),
        ]),
      ),
    );
  }
}
