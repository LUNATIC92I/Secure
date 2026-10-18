import '../core/models.dart';
import '../core/snapshot.dart';
import 'rule_pack.dart';

/// Capability a rule needs from the platform; when missing the rule is skipped
/// and reported as "unavailable" coverage instead of silently passing.
enum Capability {
  appInventory,
  deviceSettings,
  accessibilityList,
  deviceAdminList,
  notificationListeners,
  userCaStore,
  networkInfo,
  rootProbe,
  jailbreakProbe,
  passcodeState,
}

class RuleContext {
  RuleContext({required this.snapshot, required this.pack, DateTime? now}) : now = now ?? DateTime.now();

  final DeviceSnapshot snapshot;
  final RulePack pack;
  final DateTime now;

  DevicePlatform get platform => snapshot.platform;
}

/// Self-describing detection rule (see docs/DETECTION_RULES.md).
abstract class DetectionRule {
  const DetectionRule();

  String get id;
  int get version => 1;
  LText get name;
  LText get description;
  Set<DevicePlatform> get platforms;
  Set<Capability> get requires => const {};

  /// How the rule decides confidence, shown in the rule catalogue.
  LText get confidenceModel;
  LText get knownFalsePositives;
  LText get coverageLabel => name;

  /// Whether the device exposed what this rule needs.
  bool available(RuleContext ctx) => true;

  Iterable<Finding> evaluate(RuleContext ctx);

  Finding finding(
    RuleContext ctx, {
    required LText title,
    required LText description,
    required Severity severity,
    required Confidence confidence,
    required Classification classification,
    required FindingCategory category,
    required LText method,
    required LText limitations,
    String? component,
    String? componentLabel,
    Map<String, String>? evidence,
    List<RemediationStep>? remediation,
  }) => Finding(
    ruleId: id,
    ruleVersion: version,
    platform: ctx.platform,
    title: title,
    description: description,
    severity: severity,
    confidence: confidence,
    classification: classification,
    category: category,
    method: method,
    limitations: limitations,
    component: component,
    componentLabel: componentLabel,
    evidence: evidence,
    remediation: remediation,
    detectedAt: ctx.now,
  );
}

/// Frequently used remediation steps.
class Steps {
  static RemediationStep settings(String target, String en, String fr, {String? package}) =>
      RemediationStep(LText(en, fr), action: 'openSettings', target: target, package: package);

  static RemediationStep advice(String en, String fr) => RemediationStep(LText(en, fr));

  static RemediationStep uninstall(String package) => RemediationStep(
    const LText('Uninstall this app (system confirmation required)', 'Désinstaller cette application (confirmation système requise)'),
    action: 'uninstall',
    package: package,
  );

  static RemediationStep appDetails(String package) => settings(
    'appDetails',
    'Open app info to review or revoke permissions',
    'Ouvrir les infos de l’app pour revoir ou révoquer ses autorisations',
    package: package,
  );

  static final passwordsFromTrustedDevice = advice(
    'If you suspect compromise, change important account passwords from a different, trusted device and enable multi-factor authentication.',
    'En cas de doute, changez les mots de passe importants depuis un autre appareil de confiance et activez l’authentification multifacteur.',
  );
}
