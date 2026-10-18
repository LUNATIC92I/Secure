import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../../engine/url_analyzer.dart';
import '../../intel/threat_intel.dart';
import '../../state/app_state.dart';
import '../l10n.dart';
import '../theme.dart';
import '../widgets/common.dart';

class PhishingScreen extends StatefulWidget {
  const PhishingScreen({super.key, this.initialUrl});
  final String? initialUrl;
  @override
  State<PhishingScreen> createState() => _PhishingScreenState();
}

class _PhishingScreenState extends State<PhishingScreen> {
  late final _ctrl = TextEditingController(text: widget.initialUrl ?? '');
  bool _follow = false;
  bool _busy = false;
  UrlAnalysis? _result;
  List<IntelVerdict> _intel = [];

  @override
  void initState() {
    super.initState();
    if (widget.initialUrl != null) WidgetsBinding.instance.addPostFrameCallback((_) => _check());
  }

  Future<void> _check() async {
    if (_ctrl.text.trim().isEmpty) return;
    setState(() => _busy = true);
    try {
      final (a, v) = await context.read<AppState>().analyseUrl(_ctrl.text, followRedirects: _follow);
      setState(() {
        _result = a;
        _intel = v;
      });
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  /// Clipboard is read only when the user taps the paste button.
  Future<void> _paste() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    final t = data?.text;
    if (t != null) setState(() => _ctrl.text = UrlAnalyzer.extractUrl(t) ?? t.trim());
  }

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final r = _result;
    return Scaffold(
      appBar: AppBar(title: Text(context.tr('Phishing & link scanner', 'Analyse de liens'))),
      body: Responsive(
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            TextField(
              controller: _ctrl,
              keyboardType: TextInputType.url,
              autocorrect: false,
              decoration: InputDecoration(
                border: const OutlineInputBorder(),
                labelText: context.tr('Link to check', 'Lien à vérifier'),
                suffixIcon: IconButton(tooltip: context.tr('Paste from clipboard', 'Coller'), icon: const Icon(Icons.content_paste), onPressed: _paste),
              ),
              onSubmitted: (_) => _check(),
            ),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              value: _follow,
              onChanged: (v) => setState(() => _follow = v),
              title: Text(context.tr('Follow redirects', 'Suivre les redirections')),
              subtitle: Text(
                context.tr(
                  'Contacts the site to read redirect headers only; nothing is downloaded or executed.',
                  'Contacte le site pour lire uniquement les en-têtes de redirection ; rien n’est téléchargé ni exécuté.',
                ),
              ),
            ),
            FilledButton.icon(onPressed: _busy ? null : _check, icon: const Icon(Icons.search), label: Text(context.tr('Check link', 'Vérifier'))),
            Text(
              state.settings.cloudIntel
                  ? context.tr(
                      'Cloud reputation enabled (${state.settings.cloudFullUrls ? 'full URL' : 'hashed domain'} sent to your backend).',
                      'Réputation cloud activée (${state.settings.cloudFullUrls ? 'URL complète' : 'domaine haché'} envoyé à votre serveur).',
                    )
                  : context.tr(
                      'Offline analysis only. Enable cloud reputation in Threat intelligence settings.',
                      'Analyse hors ligne uniquement. Activez la réputation cloud dans les réglages de renseignement.',
                    ),
              style: const TextStyle(color: SocColors.muted, fontSize: 12),
            ),
            if (_busy)
              const Padding(
                padding: EdgeInsets.all(16),
                child: Center(child: CircularProgressIndicator()),
              ),
            if (r != null && !_busy) ..._result_(context, r),
            const SizedBox(height: 16),
            InfoBanner(
              context.tr(
                'Tip: share a link from any app to Sentinel (Android) or open sentinel://scan?url=… (iOS) to check it here.',
                'Astuce : partagez un lien depuis n’importe quelle app vers Sentinel (Android) ou ouvrez sentinel://scan?url=… (iOS).',
              ),
            ),
          ],
        ),
      ),
    );
  }

  List<Widget> _result_(BuildContext context, UrlAnalysis r) {
    final (color, label) = switch (r.verdict) {
      UrlVerdict.knownMalicious => (SocColors.red, context.tr('Known malicious', 'Malveillant connu')),
      UrlVerdict.highRisk => (SocColors.red, context.tr('High risk', 'Risque élevé')),
      UrlVerdict.suspicious => (SocColors.amber, context.tr('Suspicious', 'Suspect')),
      UrlVerdict.lowRisk => (SocColors.green, context.tr('No strong indicator', 'Aucun indicateur fort')),
      UrlVerdict.invalid => (SocColors.muted, context.tr('Not a valid link', 'Lien invalide')),
    };
    return [
      const SizedBox(height: 16),
      Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Pill(label, color),
                  const Spacer(),
                  Text(
                    '${context.tr('Risk', 'Risque')} ${r.score}/100',
                    style: TextStyle(color: color, fontWeight: FontWeight.w700),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              SelectableText(r.displayHost.isEmpty ? r.input : r.displayHost, style: const TextStyle(fontSize: 18, fontWeight: FontWeight.w700)),
              if (r.registrableDomain.isNotEmpty)
                Text('${context.tr('Registered domain', 'Domaine enregistré')}: ${r.registrableDomain}', style: const TextStyle(color: SocColors.muted)),
              if (r.knownIndicator != null)
                InfoBanner(
                  '${r.knownIndicator!.test ? '[TEST] ' : ''}${r.knownIndicator!.family} — ${r.knownIndicator!.source}',
                  color: SocColors.red,
                  icon: Icons.dangerous,
                ),
            ],
          ),
        ),
      ),
      SectionTitle(context.tr('Indicators', 'Indicateurs')),
      if (r.indicators.isEmpty) Text(context.tr('No heuristic indicator.', 'Aucun indicateur heuristique.')),
      for (final i in r.indicators)
        ListTile(
          dense: true,
          leading: const Icon(Icons.flag_outlined, color: SocColors.amber),
          title: Text(context.lt(i.label)),
          trailing: Text('+${i.weight}'),
        ),
      if (r.redirects.isNotEmpty) ...[
        SectionTitle(context.tr('Redirect chain', 'Chaîne de redirections')),
        for (final h in r.redirects)
          ListTile(
            dense: true,
            leading: Text('${h.status ?? '×'}'),
            title: Text(h.url, maxLines: 2, overflow: TextOverflow.ellipsis),
            subtitle: h.error == null ? null : Text(h.error!),
          ),
      ],
      SectionTitle(context.tr('Threat intelligence', 'Renseignement sur les menaces')),
      for (final v in _intel)
        ListTile(
          dense: true,
          leading: Icon(v.local ? Icons.phone_android : Icons.cloud_outlined),
          title: Text(v.provider),
          subtitle: Text('${v.status.name}${v.detail == null ? '' : ' — ${v.detail}'}'),
        ),
      InfoBanner(
        context.tr('A clean reputation result does not guarantee that a link is safe.', 'Une réputation propre ne garantit pas qu’un lien est sûr.'),
        color: SocColors.amber,
        icon: Icons.warning_amber_rounded,
      ),
    ];
  }
}
