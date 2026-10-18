import 'package:flutter/material.dart';

import '../core/models.dart';
import '../engine/scoring.dart';

/// French/English UI text. Rule and finding texts carry their own [LText].
extension Tr on BuildContext {
  String get lang => Localizations.localeOf(this).languageCode == 'fr' ? 'fr' : 'en';
  String tr(String en, String fr) => lang == 'fr' ? fr : en;
  String lt(LText t) => t.of(lang);
}

String severityLabel(BuildContext c, Severity s) => switch (s) {
  Severity.informational => c.tr('Info', 'Info'),
  Severity.low => c.tr('Low', 'Faible'),
  Severity.medium => c.tr('Medium', 'Moyen'),
  Severity.high => c.tr('High', 'Élevé'),
  Severity.critical => c.tr('Critical', 'Critique'),
};

String confidenceLabel(BuildContext c, Confidence s) => switch (s) {
  Confidence.low => c.tr('Low confidence', 'Confiance faible'),
  Confidence.medium => c.tr('Medium confidence', 'Confiance moyenne'),
  Confidence.high => c.tr('High confidence', 'Confiance élevée'),
};

String classificationLabel(BuildContext c, Classification s) => switch (s) {
  Classification.confirmedMalicious => c.tr('Confirmed malicious', 'Malveillant confirmé'),
  Classification.suspicious => c.tr('Suspicious', 'Suspect'),
  Classification.exposure => c.tr('Exposure', 'Exposition'),
  Classification.unverified => c.tr('To verify', 'À vérifier'),
  Classification.informational => c.tr('Informational', 'Information'),
};

String postureLabel(BuildContext c, Posture p) => switch (p) {
  Posture.strong => c.tr('Strong', 'Solide'),
  Posture.fair => c.tr('Fair', 'Correcte'),
  Posture.atRisk => c.tr('At risk', 'À risque'),
  Posture.critical => c.tr('Critical', 'Critique'),
  Posture.unknown => c.tr('Not assessed', 'Non évaluée'),
};

String modeLabel(BuildContext c, ScanMode m) => switch (m) {
  ScanMode.quick => c.tr('Quick scan', 'Analyse rapide'),
  ScanMode.comprehensive => c.tr('Comprehensive scan', 'Analyse complète'),
  ScanMode.daily => c.tr('Daily assessment', 'Évaluation quotidienne'),
  ScanMode.apk => c.tr('APK analysis', 'Analyse APK'),
  ScanMode.url => c.tr('Link check', 'Vérification de lien'),
  ScanMode.tracker => c.tr('Tracker scan', 'Recherche de traceurs'),
};

String remediationLabel(BuildContext c, RemediationStatus s) => switch (s) {
  RemediationStatus.open => c.tr('Open', 'Ouvert'),
  RemediationStatus.inProgress => c.tr('In progress', 'En cours'),
  RemediationStatus.resolved => c.tr('Resolved', 'Résolu'),
  RemediationStatus.accepted => c.tr('Risk accepted', 'Risque accepté'),
  RemediationStatus.falsePositive => c.tr('False positive', 'Faux positif'),
};

String categoryLabel(BuildContext c, FindingCategory k) => switch (k) {
  FindingCategory.malware => c.tr('Malware', 'Malware'),
  FindingCategory.stalkerware => c.tr('Stalkerware', 'Stalkerware'),
  FindingCategory.permissions => c.tr('Privileged access', 'Accès privilégiés'),
  FindingCategory.configuration => c.tr('Configuration', 'Configuration'),
  FindingCategory.integrity => c.tr('Device integrity', 'Intégrité'),
  FindingCategory.network => c.tr('Network', 'Réseau'),
  FindingCategory.privacy => c.tr('Privacy', 'Confidentialité'),
  FindingCategory.tracking => c.tr('Tracking', 'Pistage'),
  FindingCategory.microphone => c.tr('Microphone', 'Micro'),
  FindingCategory.phishing => c.tr('Phishing', 'Hameçonnage'),
  FindingCategory.apk => c.tr('APK file', 'Fichier APK'),
};

String fmtDate(BuildContext c, DateTime d) {
  final l = d.toLocal();
  String two(int v) => v.toString().padLeft(2, '0');
  return '${two(l.day)}/${two(l.month)}/${l.year} ${two(l.hour)}:${two(l.minute)}';
}

String ago(BuildContext c, DateTime d) {
  final diff = DateTime.now().difference(d);
  if (diff.inMinutes < 1) return c.tr('just now', 'à l’instant');
  if (diff.inHours < 1) return c.tr('${diff.inMinutes} min ago', 'il y a ${diff.inMinutes} min');
  if (diff.inDays < 1) return c.tr('${diff.inHours} h ago', 'il y a ${diff.inHours} h');
  return c.tr('${diff.inDays} d ago', 'il y a ${diff.inDays} j');
}
