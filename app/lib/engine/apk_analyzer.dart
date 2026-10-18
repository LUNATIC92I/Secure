import 'dart:isolate';
import 'dart:typed_data';

import 'package:archive/archive_io.dart';

import '../core/models.dart';
import '../detection/permissions.dart';
import '../detection/rule.dart';
import '../detection/rule_pack.dart';
import '../detection/yara_lite.dart';

/// Result of static analysis of a user-selected APK. Nothing is installed or run.
class ApkReport {
  ApkReport({
    required this.fileName,
    required this.sha256,
    required this.sizeBytes,
    required this.metadata,
    required this.structure,
    required this.yaraMatches,
    required this.findings,
  });

  final String fileName;
  final String sha256;
  final int sizeBytes;

  /// Package name, version, permissions, signing digests (from PackageManager).
  final Map<String, dynamic> metadata;

  /// dex count, native ABIs, embedded payloads.
  final Map<String, dynamic> structure;
  final List<YaraMatch> yaraMatches;
  final List<Finding> findings;

  String? get package => metadata['package'] as String?;
}

class YaraMatch {
  YaraMatch(this.rule, this.entry, this.strings, this.meta);
  final String rule;
  final String entry;
  final List<String> strings;
  final Map<String, String> meta;
}

class ApkAnalyzer {
  ApkAnalyzer(this.pack);

  final RulePack pack;

  static const maxEntryBytes = 64 * 1024 * 1024;

  /// [native] is the map returned by the platform's `analyzeApk`.
  Future<ApkReport> analyse({
    required String path,
    required String fileName,
    required Map<String, dynamic> native,
    required String yaraSource,
    DateTime? now,
  }) async {
    final scan = await Isolate.run(() => _scanArchive(path, yaraSource));
    return build(fileName: fileName, native: native, scan: scan, now: now ?? DateTime.now());
  }

  /// Pure function, separated for unit tests.
  ApkReport build({required String fileName, required Map<String, dynamic> native, required Map<String, dynamic> scan, required DateTime now}) {
    final sha = '${native['sha256'] ?? ''}';
    final pkg = native['package'] as String?;
    final perms = ((native['requestedPermissions'] as List?) ?? const []).map((e) => '$e').toSet();
    final services = ((native['boundServicePermissions'] as List?) ?? const []).map((e) => '$e').toSet();
    final receivers = ((native['receiverPermissions'] as List?) ?? const []).map((e) => '$e').toSet();
    final certs = ((native['signingSha256'] as List?) ?? const []).map((e) => '$e').toList();
    final yara = ((scan['yara'] as List?) ?? const [])
        .map((m) => YaraMatch(m['rule'] as String, m['entry'] as String, (m['strings'] as List).cast<String>(), Map<String, String>.from(m['meta'] as Map)))
        .toList();
    final findings = <Finding>[];

    Finding mk(
      String rule,
      String? comp,
      LText title,
      LText desc,
      Severity sev,
      Confidence conf,
      Classification cls,
      LText method,
      Map<String, String> ev, {
      List<RemediationStep>? rem,
    }) => Finding(
      ruleId: rule,
      ruleVersion: 1,
      platform: DevicePlatform.android,
      component: '$sha:${comp ?? ''}',
      componentLabel: fileName,
      title: title,
      description: desc,
      severity: sev,
      confidence: conf,
      classification: cls,
      category: FindingCategory.apk,
      method: method,
      limitations: const LText(
        'Static analysis only; behaviour at runtime is not observed.',
        'Analyse statique uniquement ; le comportement à l’exécution n’est pas observé.',
      ),
      evidence: ev,
      remediation: rem ?? (sev.index >= Severity.medium.index ? apkRemediation : const []),
      detectedAt: now,
    );

    const doNotInstall = RemediationStep(LText('Do not install this APK; delete the file.', 'N’installez pas cet APK ; supprimez le fichier.'));

    // 1. Exact indicators.
    final fileHit = pack.lookup('file_sha256', sha);
    final certHit = certs.map((c) => pack.lookup('cert_sha256', c)).nonNulls.firstOrNull;
    final pkgHit = pkg == null ? null : pack.lookup('package', pkg);
    for (final (hit, kind, confirmed) in [(fileHit, 'file hash', true), (certHit, 'signing certificate', true), (pkgHit, 'package name', false)]) {
      if (hit == null) continue;
      findings.add(
        mk(
          'APK-IOC-${kind.split(' ').first.toUpperCase()}',
          hit.value,
          LText('${hit.test ? '[TEST] ' : ''}Known ${hit.category}: ${hit.family}', '${hit.test ? '[TEST] ' : ''}${hit.category} connu : ${hit.family}'),
          LText('The $kind matches an indicator from ${hit.source}.', 'Le $kind correspond à un indicateur de ${hit.source}.'),
          Severity.critical,
          confirmed ? Confidence.high : Confidence.medium,
          confirmed ? Classification.confirmedMalicious : Classification.suspicious,
          LText('Indicator match ($kind), rule pack v${pack.version}', 'Correspondance ($kind), pack v${pack.version}'),
          {'indicator': hit.value, 'source': hit.source, 'family': hit.family},
          rem: [doNotInstall],
        ),
      );
    }

    // 2. Capability analysis.
    final groups = <String>{};
    var capScore = 0;
    for (final p in perms) {
      final s = sensitiveByName[p];
      if (s != null && groups.add(s.group)) capScore += s.weight;
    }
    final binds = <String>[
      if (services.contains(permBindAccessibility)) 'accessibility',
      if (receivers.contains(permBindDeviceAdmin)) 'deviceAdmin',
      if (services.contains(permBindNotificationListener)) 'notificationListener',
    ];
    final surveillance = capScore >= 8 && binds.isNotEmpty;
    if (surveillance || capScore >= 10) {
      findings.add(
        mk(
          'APK-CAP-001',
          'capabilities',
          const LText('Surveillance-capable permission set', 'Ensemble d’autorisations permettant la surveillance'),
          const LText(
            'The app declares access to several private data sources together with privileged services. Legitimate for some apps; typical of spyware.',
            'L’app déclare l’accès à plusieurs sources de données privées et à des services privilégiés. Légitime pour certaines apps ; typique des logiciels espions.',
          ),
          surveillance ? Severity.medium : Severity.low,
          Confidence.low,
          Classification.suspicious,
          const LText('Manifest permission correlation', 'Corrélation des autorisations du manifeste'),
          {'groups': groups.join(', '), 'privilegedServices': binds.join(', '), 'score': '$capScore'},
        ),
      );
    }
    if (perms.contains('android.permission.SEND_SMS') &&
        perms.contains('android.permission.RECEIVE_SMS') &&
        !perms.contains('android.permission.READ_CONTACTS')) {
      findings.add(
        mk(
          'APK-CAP-002',
          'sms',
          const LText('Can silently send and intercept SMS', 'Peut envoyer et intercepter des SMS'),
          const LText('Common in premium-SMS fraud and one-time-code theft.', 'Courant dans la fraude aux SMS surtaxés et le vol de codes.'),
          Severity.medium,
          Confidence.low,
          Classification.suspicious,
          const LText('Manifest permissions', 'Autorisations du manifeste'),
          {'permissions': 'SEND_SMS, RECEIVE_SMS'},
        ),
      );
    }
    if (native['debuggable'] == true) {
      findings.add(
        mk(
          'APK-CFG-001',
          'debuggable',
          const LText('Debuggable build', 'Build débogable'),
          const LText(
            'Release apps are not debuggable; this may be a repackaged or test build.',
            'Une app publiée n’est pas débogable ; build reconditionnée ou de test possible.',
          ),
          Severity.low,
          Confidence.high,
          Classification.exposure,
          const LText('ApplicationInfo flags', 'Drapeaux ApplicationInfo'),
          {'debuggable': 'true'},
        ),
      );
    }
    final target = (native['targetSdk'] as num?)?.toInt();
    if (target != null && target < 26) {
      findings.add(
        mk(
          'APK-CFG-002',
          'targetSdk',
          LText('Targets an old Android API ($target)', 'Cible une ancienne API Android ($target)'),
          const LText(
            'Old targets bypass runtime-permission protections introduced in newer Android versions.',
            'Une cible ancienne contourne des protections récentes des autorisations.',
          ),
          Severity.low,
          Confidence.high,
          Classification.exposure,
          const LText('Manifest targetSdkVersion', 'targetSdkVersion du manifeste'),
          {'targetSdk': '$target'},
        ),
      );
    }
    if (certs.isEmpty && native['parsed'] == true) {
      findings.add(
        mk(
          'APK-SIG-001',
          'unsigned',
          const LText('No valid signature found', 'Aucune signature valide'),
          const LText(
            'Android refuses to install unsigned APKs; this file may be corrupted or tampered with.',
            'Android refuse les APK non signés ; fichier corrompu ou altéré possible.',
          ),
          Severity.medium,
          Confidence.medium,
          Classification.suspicious,
          const LText('Signing block inspection', 'Inspection du bloc de signature'),
          {},
        ),
      );
    }
    if (native['parsed'] != true) {
      findings.add(
        mk(
          'APK-PARSE-001',
          'parse',
          const LText('Not a valid Android package', 'Pas un paquet Android valide'),
          const LText('PackageManager could not parse the manifest.', 'PackageManager n’a pas pu lire le manifeste.'),
          Severity.informational,
          Confidence.high,
          Classification.informational,
          const LText('PackageManager.getPackageArchiveInfo', 'PackageManager.getPackageArchiveInfo'),
          {},
        ),
      );
    }

    // 3. Structure.
    final embedded = ((scan['embeddedPayloads'] as List?) ?? const []).cast<String>();
    if (embedded.isNotEmpty) {
      findings.add(
        mk(
          'APK-STR-001',
          'payload',
          const LText('Embedded executable payload', 'Charge exécutable embarquée'),
          const LText(
            'Code hidden in assets (DEX/JAR/APK) is often loaded at runtime to evade review.',
            'Du code caché dans les assets est souvent chargé à l’exécution pour échapper à l’analyse.',
          ),
          Severity.medium,
          Confidence.medium,
          Classification.suspicious,
          const LText('Archive structure inspection', 'Inspection de la structure de l’archive'),
          {'entries': embedded.take(5).join(', ')},
        ),
      );
    }

    // 4. YARA-lite matches (heuristic unless the rule declares itself an exact signature).
    for (final m in yara) {
      final sev = enumByName(Severity.values, m.meta['severity'], Severity.low);
      final exact = m.meta['type'] == 'signature';
      findings.add(
        mk(
          'APK-YARA-${m.rule}',
          m.rule,
          LText('Pattern: ${m.meta['title_en'] ?? m.rule}', 'Motif : ${m.meta['title_fr'] ?? m.meta['title_en'] ?? m.rule}'),
          LText(m.meta['description'] ?? 'YARA rule ${m.rule} matched.', m.meta['description_fr'] ?? m.meta['description'] ?? 'Règle YARA ${m.rule} détectée.'),
          sev,
          exact ? Confidence.high : Confidence.low,
          exact ? Classification.confirmedMalicious : Classification.suspicious,
          LText('YARA-lite rule ${m.rule} on ${m.entry}', 'Règle YARA-lite ${m.rule} sur ${m.entry}'),
          {'entry': m.entry, 'strings': m.strings.join(', ')},
          rem: exact ? [doNotInstall] : null,
        ),
      );
    }

    return ApkReport(
      fileName: fileName,
      sha256: sha,
      sizeBytes: (native['sizeBytes'] as num?)?.toInt() ?? 0,
      metadata: native,
      structure: Map<String, dynamic>.from(scan)..remove('yara'),
      yaraMatches: yara,
      findings: findings..sort((a, b) => b.severity.index.compareTo(a.severity.index)),
    );
  }
}

/// Runs in a background isolate: reads the ZIP central directory and scans code entries.
Map<String, dynamic> _scanArchive(String path, String yaraSource) {
  final rules = YaraLite.parse(yaraSource);
  final input = InputFileStream(path);
  try {
    final archive = ZipDecoder().decodeStream(input);
    var dex = 0;
    final abis = <String>{};
    final embedded = <String>[];
    final matches = <Map<String, dynamic>>[];
    for (final f in archive.files) {
      if (!f.isFile) continue;
      final name = f.name;
      if (RegExp(r'^classes\d*\.dex$').hasMatch(name)) dex++;
      final lib = RegExp(r'^lib/([^/]+)/').firstMatch(name);
      if (lib != null) abis.add(lib.group(1)!);
      final lower = name.toLowerCase();
      final isPayload =
          (lower.startsWith('assets/') || lower.startsWith('res/raw/')) &&
          (lower.endsWith('.dex') || lower.endsWith('.jar') || lower.endsWith('.apk') || lower.endsWith('.so'));
      if (isPayload) embedded.add(name);
      final scanThis = RegExp(r'^classes\d*\.dex$').hasMatch(name) || isPayload || lower.endsWith('.txt') && f.size < 1 << 20;
      if (!scanThis || f.size > ApkAnalyzer.maxEntryBytes) continue;
      final Uint8List bytes = f.content;
      for (final r in rules) {
        final hit = r.match(bytes);
        if (hit != null) matches.add({'rule': r.name, 'entry': name, 'strings': hit.toList(), 'meta': r.meta});
      }
    }
    // Keep one match per rule (first entry) to avoid duplicates across multidex.
    final seen = <String>{};
    matches.retainWhere((m) => seen.add(m['rule'] as String));
    return {'entries': archive.files.length, 'dexCount': dex, 'nativeAbis': abis.toList()..sort(), 'embeddedPayloads': embedded, 'yara': matches};
  } finally {
    input.closeSync();
  }
}

/// Scans an arbitrary small file (e.g. a test fixture) with the same rules.
List<String> yaraScanBytes(Uint8List bytes, List<YaraRule> rules) => [
  for (final r in rules)
    if (r.match(bytes) != null) r.name,
];

// Shared remediation for APK findings shown in the UI.
final apkRemediation = [
  Steps.advice(
    'Only install apps from an official store or a developer you trust.',
    'N’installez que des apps d’un store officiel ou d’un développeur de confiance.',
  ),
];
