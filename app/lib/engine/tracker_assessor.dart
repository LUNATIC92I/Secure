import '../core/models.dart';

class TrackerSighting {
  TrackerSighting({required this.address, required this.kind, required this.firstSeen, required this.lastSeen, this.scans = 1, this.rssi});

  final String address;
  final String kind;
  DateTime firstSeen;
  DateTime lastSeen;
  int scans;
  int? rssi;

  Map<String, dynamic> toJson() => {
        'address': address,
        'kind': kind,
        'firstSeen': firstSeen.toIso8601String(),
        'lastSeen': lastSeen.toIso8601String(),
        'scans': scans,
        'rssi': rssi,
      };

  factory TrackerSighting.fromJson(Map<String, dynamic> j) => TrackerSighting(
        address: j['address'] as String,
        kind: j['kind'] as String,
        firstSeen: DateTime.parse(j['firstSeen'] as String),
        lastSeen: DateTime.parse(j['lastSeen'] as String),
        scans: (j['scans'] as num?)?.toInt() ?? 1,
        rssi: (j['rssi'] as num?)?.toInt(),
      );
}

/// Turns repeated BLE sightings into tracking-risk findings.
///
/// A tracker separated from its owner keeps the same advertised identifier for hours,
/// so seeing the same identifier across scans spread over time (while you move) is the
/// signal used by OS unknown-tracker alerts. One sighting means only "a tracker is nearby".
class TrackerAssessor {
  static const persistence = Duration(minutes: 30);
  static const retention = Duration(days: 3);

  static const kindLabels = {
    'apple_findmy': LText('Apple Find My accessory (e.g. AirTag) away from its owner', 'Accessoire Localiser d’Apple (ex. AirTag) éloigné de son propriétaire'),
    'samsung_smarttag': LText('Samsung SmartTag', 'Samsung SmartTag'),
    'tile': LText('Tile tracker', 'Traceur Tile'),
    'google_fmdn': LText('Find My Device network tag', 'Balise du réseau Localiser mon appareil'),
  };

  /// Merges a scan into the history and returns the updated history.
  static List<TrackerSighting> merge(List<TrackerSighting> history, List<Map<String, dynamic>> devices, DateTime now) {
    final byAddr = {for (final s in history) s.address: s};
    for (final d in devices) {
      final addr = d['address'] as String?;
      final kind = d['kind'] as String?;
      if (addr == null || kind == null) continue;
      final existing = byAddr[addr];
      if (existing == null) {
        byAddr[addr] = TrackerSighting(address: addr, kind: kind, firstSeen: now, lastSeen: now, rssi: (d['rssi'] as num?)?.toInt());
      } else {
        existing
          ..lastSeen = now
          ..scans += 1
          ..rssi = (d['rssi'] as num?)?.toInt();
      }
    }
    return byAddr.values.where((s) => now.difference(s.lastSeen) < retention).toList();
  }

  static List<Finding> assess(List<TrackerSighting> history, Set<String> seenNow, DevicePlatform platform, DateTime now) {
    final out = <Finding>[];
    for (final s in history.where((s) => seenNow.contains(s.address))) {
      final persistent = s.scans >= 2 && s.lastSeen.difference(s.firstSeen) >= persistence;
      final label = kindLabels[s.kind] ?? LText(s.kind, s.kind);
      out.add(Finding(
        ruleId: 'TRK-001',
        ruleVersion: 1,
        platform: platform,
        component: '${s.kind}:${s.address}',
        componentLabel: label.en,
        detectedAt: now,
        title: persistent
            ? LText('Tracker seen repeatedly near you: ${label.en}', 'Traceur vu à plusieurs reprises près de vous : ${label.fr}')
            : LText('Tracker nearby: ${label.en}', 'Traceur à proximité : ${label.fr}'),
        description: persistent
            ? LText('The same tracker identifier was observed in ${s.scans} scans over ${s.lastSeen.difference(s.firstSeen).inMinutes} minutes. If you moved between scans, it may be travelling with you.',
                'Le même identifiant a été observé dans ${s.scans} scans sur ${s.lastSeen.difference(s.firstSeen).inMinutes} minutes. Si vous vous êtes déplacé entre les scans, il voyage peut-être avec vous.')
            : const LText('Trackers belonging to people around you are common (public transport, cafés). Scan again later in a different place to see if it follows you.',
                'Les traceurs des personnes autour de vous sont courants (transports, cafés). Rescannez plus tard ailleurs pour voir s’il vous suit.'),
        severity: persistent ? Severity.medium : Severity.informational,
        confidence: persistent ? Confidence.medium : Confidence.low,
        classification: persistent ? Classification.unverified : Classification.informational,
        category: FindingCategory.tracking,
        method: const LText('Foreground Bluetooth LE advertisement scan', 'Scan Bluetooth LE au premier plan'),
        limitations: const LText('Identifiers rotate; trackers not advertising (or filtered by the OS) are invisible. This is not a universal tracker detector.',
            'Les identifiants changent ; les traceurs qui n’émettent pas (ou filtrés par l’OS) sont invisibles. Ce n’est pas un détecteur universel.'),
        evidence: {'identifier': s.address, 'scans': '${s.scans}', 'firstSeen': s.firstSeen.toIso8601String(), 'rssi': '${s.rssi}'},
        remediation: [
          platform == DevicePlatform.ios
              ? const RemediationStep(LText('Use Find My → Items → Identify Found Item, and keep Tracking Notifications on.',
                  'Utilisez Localiser → Objets → Identifier un objet trouvé et gardez les notifications de suivi activées.'))
              : const RemediationStep(LText('Use Settings → Safety & emergency → Unknown tracker alerts → Scan now.',
                  'Utilisez Paramètres → Sécurité et urgence → Alertes de traceurs inconnus → Rechercher.')),
          const RemediationStep(LText('If you feel unsafe, contact the police; do not destroy the tracker (it may be evidence).',
              'Si vous vous sentez en danger, contactez la police ; ne détruisez pas le traceur (preuve possible).')),
        ],
      ));
    }
    return out;
  }
}
