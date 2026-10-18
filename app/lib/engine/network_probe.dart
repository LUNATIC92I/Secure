import 'dart:async';
import 'dart:io';

import '../core/models.dart';

class ProbeResult {
  ProbeResult(this.findings, {required this.completed});
  final List<Finding> findings;
  final bool completed;
}

/// Opt-in connectivity probe. It opens TLS connections to a few well-known hosts with
/// normal certificate validation (never bypassed) and reports validation failures,
/// which indicate interception, a captive portal or a broken network.
class NetworkProbe {
  NetworkProbe({this.hosts = const ['www.google.com', 'cloudflare.com', 'www.apple.com'], this.timeout = const Duration(seconds: 6)});

  final List<String> hosts;
  final Duration timeout;

  Future<ProbeResult> run(DevicePlatform platform, DateTime now) async {
    final failures = <String, String>{};
    var reachable = 0;
    for (final host in hosts) {
      try {
        final socket = await SecureSocket.connect(host, 443, timeout: timeout);
        final cert = socket.peerCertificate;
        socket.destroy();
        reachable++;
        if (cert == null) failures[host] = 'no peer certificate';
      } on HandshakeException catch (e) {
        final msg = '${e.osError?.message ?? ''} ${e.message}';
        // Only certificate problems count; truncated handshakes are ordinary network noise.
        if (msg.toUpperCase().contains('CERTIFICATE')) failures[host] = msg.trim();
      } on SocketException catch (_) {
        // Unreachable is not a certificate problem; ignore.
      } on TimeoutException catch (_) {}
    }
    final findings = <Finding>[];
    if (failures.isNotEmpty) {
      findings.add(
        Finding(
          ruleId: 'NET-TLS-001',
          ruleVersion: 1,
          platform: platform,
          component: 'tls',
          detectedAt: now,
          title: const LText('TLS certificate validation failed', 'Échec de validation des certificats TLS'),
          description: const LText(
            'Connections to well-known sites presented certificates the system does not trust. This happens behind captive portals, with corporate inspection proxies, or during a man-in-the-middle attack.',
            'Des connexions vers des sites connus ont présenté des certificats non reconnus par le système. Cela arrive derrière un portail captif, un proxy d’inspection d’entreprise ou lors d’une attaque de l’homme du milieu.',
          ),
          severity: Severity.high,
          confidence: failures.length >= 2 ? Confidence.high : Confidence.medium,
          classification: Classification.suspicious,
          category: FindingCategory.network,
          method: const LText('TLS handshake with system trust store', 'Poignée de main TLS avec le magasin de confiance système'),
          limitations: const LText(
            'Targeted interception of other domains would not be visible.',
            'Une interception ciblée d’autres domaines ne serait pas visible.',
          ),
          evidence: failures,
          remediation: const [
            RemediationStep(
              LText(
                'Disconnect from this network and avoid signing in to accounts until resolved.',
                'Déconnectez-vous de ce réseau et évitez de vous connecter à vos comptes.',
              ),
            ),
            RemediationStep(LText('Open Wi-Fi settings', 'Ouvrir les réglages Wi-Fi'), action: 'openSettings', target: 'wifi'),
          ],
        ),
      );
    }
    return ProbeResult(findings, completed: reachable > 0 || failures.isNotEmpty);
  }
}
