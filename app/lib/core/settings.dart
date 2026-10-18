/// User preferences. Defaults are the privacy-preserving choice.
class AppSettings {
  AppSettings({
    this.onboarded = false,
    this.languageCode,
    this.dailyAssessment = false,
    this.notificationsEnabled = false,
    this.notifyHighOnly = true,
    this.networkChecks = false,
    this.cloudIntel = false,
    this.cloudFullUrls = false,
    this.backendUrl = '',
    this.backendToken = '',
    this.retentionDays = 90,
    this.brandName = 'Sentinel Mobile SOC',
    this.minRulePackVersion = 0,
  });

  bool onboarded;
  String? languageCode;
  bool dailyAssessment;
  bool notificationsEnabled;
  bool notifyHighOnly;

  /// Opt-in TLS / connectivity probe to public hosts.
  bool networkChecks;

  /// Explicit consent to send hashes / URLs to the configured backend.
  bool cloudIntel;
  bool cloudFullUrls;
  String backendUrl;
  String backendToken;
  int retentionDays;
  String brandName;

  /// Highest rule-pack version ever accepted (rollback protection).
  int minRulePackVersion;

  bool get backendConfigured => Uri.tryParse(backendUrl)?.hasScheme == true && backendToken.isNotEmpty;

  Map<String, dynamic> toJson() => {
        'onboarded': onboarded,
        'languageCode': languageCode,
        'dailyAssessment': dailyAssessment,
        'notificationsEnabled': notificationsEnabled,
        'notifyHighOnly': notifyHighOnly,
        'networkChecks': networkChecks,
        'cloudIntel': cloudIntel,
        'cloudFullUrls': cloudFullUrls,
        'backendUrl': backendUrl,
        'backendToken': backendToken,
        'retentionDays': retentionDays,
        'brandName': brandName,
        'minRulePackVersion': minRulePackVersion,
      };

  factory AppSettings.fromJson(Map<String, dynamic> j) => AppSettings(
        onboarded: j['onboarded'] == true,
        languageCode: j['languageCode'] as String?,
        dailyAssessment: j['dailyAssessment'] == true,
        notificationsEnabled: j['notificationsEnabled'] == true,
        notifyHighOnly: j['notifyHighOnly'] != false,
        networkChecks: j['networkChecks'] == true,
        cloudIntel: j['cloudIntel'] == true,
        cloudFullUrls: j['cloudFullUrls'] == true,
        backendUrl: j['backendUrl'] as String? ?? '',
        backendToken: j['backendToken'] as String? ?? '',
        retentionDays: (j['retentionDays'] as num?)?.toInt() ?? 90,
        brandName: j['brandName'] as String? ?? 'Sentinel Mobile SOC',
        minRulePackVersion: (j['minRulePackVersion'] as num?)?.toInt() ?? 0,
      );
}
