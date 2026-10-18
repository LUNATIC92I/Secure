import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../engine/apk_analyzer.dart';
import '../../intel/threat_intel.dart';
import '../../state/app_state.dart';
import '../l10n.dart';
import '../theme.dart';
import '../widgets/common.dart';
import 'finding_detail_screen.dart';

class ApkScreen extends StatefulWidget {
  const ApkScreen({super.key});
  @override
  State<ApkScreen> createState() => _ApkScreenState();
}

class _ApkScreenState extends State<ApkScreen> {
  bool _busy = false;
  ApkReport? _report;
  List<IntelVerdict> _intel = [];
  String? _error;

  Future<void> _pick() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final r = await context.read<AppState>().analyseApk();
      if (r != null) {
        setState(() {
          _report = r.$1;
          _intel = r.$2;
        });
      }
    } catch (e) {
      setState(() => _error = '$e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final r = _report;
    return Scaffold(
      appBar: AppBar(title: Text(context.tr('APK analysis', 'Analyse d’APK'))),
      body: Responsive(
        child: ListView(padding: const EdgeInsets.all(16), children: [
          InfoBanner(context.tr(
              'Select an APK file. Sentinel computes its SHA-256, reads its manifest and signature, and scans its code with local YARA-lite rules. The file is never installed, executed or uploaded.',
              'Choisissez un fichier APK. Sentinel calcule son SHA-256, lit manifeste et signature et analyse le code avec des règles YARA-lite locales. Le fichier n’est jamais installé, exécuté ni envoyé.')),
          FilledButton.icon(onPressed: _busy ? null : _pick, icon: const Icon(Icons.file_open), label: Text(context.tr('Choose APK file', 'Choisir un fichier APK'))),
          if (state.settings.cloudIntel)
            Text(context.tr('The hash (not the file) will be checked with your backend.', 'L’empreinte (pas le fichier) sera vérifiée auprès de votre serveur.'),
                style: const TextStyle(color: SocColors.muted, fontSize: 12)),
          if (_busy) const Padding(padding: EdgeInsets.all(24), child: Center(child: ScanRadar(size: 110))),
          if (_error != null) InfoBanner(_error!, color: SocColors.red, icon: Icons.error_outline),
          if (r != null && !_busy) ...[
            SectionTitle(context.tr('File', 'Fichier')),
            Card(
              child: Column(children: [
                ListTile(dense: true, title: Text(context.tr('Name', 'Nom')), subtitle: Text(r.fileName)),
                ListTile(dense: true, title: const Text('SHA-256'), subtitle: SelectableText(r.sha256)),
                ListTile(dense: true, title: Text(context.tr('Package', 'Paquet')), subtitle: Text('${r.package ?? '-'}  ${r.metadata['versionName'] ?? ''}')),
                ListTile(dense: true, title: Text(context.tr('Size', 'Taille')), subtitle: Text('${(r.sizeBytes / 1048576).toStringAsFixed(2)} MB')),
                ListTile(dense: true, title: Text(context.tr('Signing certificate', 'Certificat de signature')), subtitle: SelectableText(((r.metadata['signingSha256'] as List?) ?? const []).join('\n'))),
                ListTile(
                  dense: true,
                  title: Text(context.tr('Structure', 'Structure')),
                  subtitle: Text('dex: ${r.structure['dexCount']} · ABI: ${(r.structure['nativeAbis'] as List?)?.join(', ') ?? '-'} · ${context.tr('entries', 'entrées')}: ${r.structure['entries']}'),
                ),
                ListTile(
                  dense: true,
                  title: Text(context.tr('Permissions requested', 'Autorisations demandées')),
                  subtitle: Text(((r.metadata['requestedPermissions'] as List?) ?? const []).map((p) => '$p'.split('.').last).join(', ')),
                ),
              ]),
            ),
            SectionTitle(context.tr('Threat intelligence', 'Renseignement')),
            for (final v in _intel)
              ListTile(dense: true, leading: Icon(v.local ? Icons.phone_android : Icons.cloud_outlined), title: Text(v.provider), subtitle: Text('${v.status.name}${v.detail == null ? '' : ' — ${v.detail}'}')),
            SectionTitle(context.tr('Findings', 'Résultats')),
            if (r.findings.isEmpty)
              InfoBanner(context.tr('No indicator found. Static analysis cannot prove an app is safe.', 'Aucun indicateur. Une analyse statique ne peut pas prouver qu’une app est sûre.'),
                  color: SocColors.green, icon: Icons.verified_outlined),
            for (final f in r.findings) FindingTile(f, onTap: () => Navigator.push(context, MaterialPageRoute(builder: (_) => FindingDetailScreen(finding: f)))),
          ],
        ]),
      ),
    );
  }
}
