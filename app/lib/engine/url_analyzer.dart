import 'dart:async';
import 'dart:io';
import 'dart:math';

import '../core/models.dart';
import '../detection/rule_pack.dart';

class UrlIndicator {
  const UrlIndicator(this.id, this.label, this.weight);
  final String id;
  final LText label;

  /// Contribution to the 0-100 heuristic risk score.
  final int weight;
}

enum UrlVerdict { knownMalicious, highRisk, suspicious, lowRisk, invalid }

class RedirectHop {
  RedirectHop(this.url, this.status, {this.error});
  final String url;
  final int? status;
  final String? error;
}

class UrlAnalysis {
  UrlAnalysis({
    required this.input,
    required this.uri,
    required this.displayHost,
    required this.registrableDomain,
    required this.indicators,
    required this.verdict,
    required this.score,
    this.knownIndicator,
    this.redirects = const [],
  });

  final String input;
  final Uri? uri;

  /// Host decoded from punycode so homographs are visible.
  final String displayHost;
  final String registrableDomain;
  final List<UrlIndicator> indicators;
  final UrlVerdict verdict;
  final int score;
  final Indicator? knownIndicator;
  final List<RedirectHop> redirects;

  UrlAnalysis withRedirects(List<RedirectHop> hops, UrlAnalysis Function(String) analyse) {
    final extra = <UrlIndicator>[];
    final finalHop = hops.lastWhere((h) => h.error == null, orElse: () => RedirectHop(input, null));
    if (hops.length > 3) {
      extra.add(UrlIndicator('redirect_chain', LText('Long redirect chain (${hops.length} hops)', 'Longue chaîne de redirections (${hops.length} sauts)'), 10));
    }
    UrlAnalysis? destination;
    if (finalHop.url != input) {
      destination = analyse(finalHop.url);
      if (destination.registrableDomain != registrableDomain) {
        extra.add(
          UrlIndicator(
            'redirect_cross_domain',
            LText('Redirects to a different domain: ${destination.displayHost}', 'Redirige vers un autre domaine : ${destination.displayHost}'),
            10,
          ),
        );
      }
      extra.addAll(
        destination.indicators.map((i) => UrlIndicator('dest_${i.id}', LText('Destination: ${i.label.en}', 'Destination : ${i.label.fr}'), i.weight)),
      );
    }
    final all = [...indicators, ...extra];
    final known = knownIndicator ?? destination?.knownIndicator;
    final s = min(100, all.fold<int>(0, (a, b) => a + b.weight));
    return UrlAnalysis(
      input: input,
      uri: uri,
      displayHost: displayHost,
      registrableDomain: registrableDomain,
      indicators: all,
      verdict: UrlAnalyzer.verdictFor(s, known),
      score: s,
      knownIndicator: known,
      redirects: hops,
    );
  }
}

/// Offline phishing heuristics. A clean result never means "safe": it only means none
/// of these indicators were present and the URL is not in the local feed.
class UrlAnalyzer {
  UrlAnalyzer(this.pack);

  final RulePack pack;

  /// Brand keyword → legitimate registrable domains.
  static const brands = <String, List<String>>{
    'paypal': ['paypal.com', 'paypal.fr', 'paypal.me'],
    'apple': ['apple.com', 'icloud.com'],
    'icloud': ['icloud.com', 'apple.com'],
    'google': ['google.com', 'google.fr', 'gmail.com', 'youtube.com', 'goo.gl', 'g.co'],
    'microsoft': ['microsoft.com', 'live.com', 'office.com', 'microsoftonline.com', 'outlook.com'],
    'office365': ['office.com', 'microsoft.com'],
    'outlook': ['outlook.com', 'live.com', 'microsoft.com'],
    'amazon': ['amazon.com', 'amazon.fr', 'amazon.de', 'amazon.co.uk', 'amazon.es', 'amazon.it'],
    'netflix': ['netflix.com'],
    'facebook': ['facebook.com', 'fb.com', 'fb.me'],
    'instagram': ['instagram.com'],
    'whatsapp': ['whatsapp.com', 'whatsapp.net', 'wa.me'],
    'ameli': ['ameli.fr'],
    'impots': ['impots.gouv.fr'],
    'antai': ['antai.gouv.fr'],
    'franceconnect': ['franceconnect.gouv.fr'],
    'laposte': ['laposte.fr', 'laposte.net', 'labanquepostale.fr'],
    'labanquepostale': ['labanquepostale.fr'],
    'chronopost': ['chronopost.fr'],
    'colissimo': ['colissimo.fr', 'laposte.fr'],
    'creditagricole': ['credit-agricole.fr', 'ca-paris.fr'],
    'bnpparibas': ['bnpparibas', 'mabanque.bnpparibas', 'bnpparibas.com', 'bnpparibas.fr'],
    'societegenerale': ['societegenerale.fr', 'societegenerale.com'],
    'doctolib': ['doctolib.fr', 'doctolib.com'],
    'dhl': ['dhl.com', 'dhl.fr', 'dhl.de'],
    'fedex': ['fedex.com'],
  };

  static const shorteners = {
    'bit.ly',
    'tinyurl.com',
    't.co',
    'goo.gl',
    'is.gd',
    'cutt.ly',
    'rebrand.ly',
    'ow.ly',
    's.id',
    'shorturl.at',
    'rb.gy',
    'tiny.cc',
    'buff.ly',
  };

  /// TLDs over-represented in abuse reports. Statistical, never conclusive.
  static const riskyTlds = {'zip', 'mov', 'top', 'xyz', 'click', 'country', 'gq', 'tk', 'ml', 'cf', 'work', 'rest', 'support', 'icu', 'cam'};

  static const _secondLevel = {
    'co.uk',
    'org.uk',
    'ac.uk',
    'gov.uk',
    'com.au',
    'net.au',
    'co.jp',
    'co.nz',
    'com.br',
    'com.mx',
    'co.in',
    'gouv.fr',
    'asso.fr',
    'com.tr',
    'co.za',
    'com.cn',
  };

  static const _lureWords = [
    'login',
    'signin',
    'verify',
    'verification',
    'secure',
    'account',
    'update',
    'password',
    'wallet',
    'confirm',
    'unlock',
    'suspend',
    'billing',
    'invoice',
    'colis',
    'livraison',
    'remboursement',
  ];

  static String registrable(String host) {
    final parts = host.split('.').where((p) => p.isNotEmpty).toList();
    if (parts.length <= 2) return parts.join('.');
    final last2 = parts.sublist(parts.length - 2).join('.');
    if (_secondLevel.contains(last2)) return parts.sublist(parts.length - 3).join('.');
    return last2;
  }

  static UrlVerdict verdictFor(int score, Indicator? known) {
    if (known != null) return UrlVerdict.knownMalicious;
    if (score >= 60) return UrlVerdict.highRisk;
    if (score >= 25) return UrlVerdict.suspicious;
    return UrlVerdict.lowRisk;
  }

  /// Extracts the first URL-looking token from shared text.
  static String? extractUrl(String text) {
    final m = RegExp(r'''((?:https?|ftp)://[^\s<>"']+|(?:www\.)[^\s<>"']+|[a-z]+:[^\s<>"']+)''', caseSensitive: false).firstMatch(text.trim());
    return m?.group(1);
  }

  UrlAnalysis analyse(String raw) {
    var input = raw.trim();
    if (input.isEmpty || input.length > 4096) return _invalid(input);
    if (!RegExp(r'^[a-zA-Z][a-zA-Z0-9+.-]*:').hasMatch(input)) input = 'http://$input';
    final Uri uri;
    try {
      uri = Uri.parse(input);
    } on FormatException {
      return _invalid(raw);
    }
    final ind = <UrlIndicator>[];
    final scheme = uri.scheme.toLowerCase();
    if (const {'javascript', 'data', 'file', 'intent', 'vbscript', 'blob'}.contains(scheme)) {
      ind.add(UrlIndicator('dangerous_scheme', LText('Dangerous scheme “$scheme:”', 'Schéma dangereux « $scheme: »'), 70));
      return _result(raw, uri, uri.host, ind);
    }
    if (scheme != 'http' && scheme != 'https') {
      ind.add(UrlIndicator('unusual_scheme', LText('Unusual scheme “$scheme:”', 'Schéma inhabituel « $scheme: »'), 20));
    }
    final host = uri.host.toLowerCase();
    if (host.isEmpty) return _invalid(raw);

    // Dart percent-encodes raw Unicode hosts; punycode hosts are decoded label by label.
    final unicodeHost = host.contains('%');
    final decoded = unicodeHost ? Uri.decodeComponent(host) : host.split('.').map(Punycode.decodeLabel).join('.');
    if (scheme == 'http') ind.add(const UrlIndicator('no_tls', LText('Not encrypted (http)', 'Non chiffré (http)'), 8));
    if (uri.userInfo.isNotEmpty) {
      ind.add(
        const UrlIndicator(
          'userinfo',
          LText('Contains “user@” before the host (classic disguise)', 'Contient « utilisateur@ » avant l’hôte (déguisement classique)'),
          45,
        ),
      );
    }
    if (RegExp(r'^\d{1,3}(\.\d{1,3}){3}$').hasMatch(host) || host.contains(':')) {
      ind.add(const UrlIndicator('ip_host', LText('Uses a raw IP address instead of a domain', 'Utilise une adresse IP au lieu d’un domaine'), 30));
    }
    if (unicodeHost || host.split('.').any((l) => l.startsWith('xn--'))) {
      ind.add(UrlIndicator('punycode', LText('Internationalised domain: displays as “$decoded”', 'Domaine internationalisé : s’affiche « $decoded »'), 20));
      if (decoded.split('.').any(Punycode.isMixedScript)) {
        ind.add(const UrlIndicator('homograph', LText('Mixes alphabets (possible look-alike domain)', 'Mélange d’alphabets (possible domaine sosie)'), 45));
      }
    }
    final labels = host.split('.');
    if (labels.length > 4) {
      ind.add(UrlIndicator('deep_subdomains', LText('${labels.length - 2} levels of subdomains', '${labels.length - 2} niveaux de sous-domaines'), 10));
    }
    if ('-'.allMatches(host).length >= 3) ind.add(const UrlIndicator('hyphens', LText('Many hyphens in host', 'Nombreux tirets dans l’hôte'), 8));
    final reg = registrable(host);
    final tld = labels.last;
    if (riskyTlds.contains(tld)) {
      ind.add(UrlIndicator('risky_tld', LText('Top-level domain “.$tld” is frequently abused', 'Le domaine « .$tld » est souvent abusé'), 10));
    }
    if (shorteners.contains(host)) {
      ind.add(const UrlIndicator('shortener', LText('Link shortener hides the real destination', 'Le raccourcisseur masque la vraie destination'), 15));
    }
    if (uri.hasPort && uri.port != 80 && uri.port != 443) {
      ind.add(UrlIndicator('port', LText('Non-standard port ${uri.port}', 'Port non standard ${uri.port}'), 8));
    }

    final hostNoReg = host.length > reg.length ? host.substring(0, host.length - reg.length) : '';
    final flatHost = host.replaceAll('-', '');
    for (final b in brands.entries) {
      final legit = b.value.any((d) => reg == d || host == d || host.endsWith('.$d'));
      if (legit) continue;
      if (flatHost.contains(b.key) || hostNoReg.contains(b.key)) {
        ind.add(
          UrlIndicator(
            'brand_${b.key}',
            LText('Mentions “${b.key}” but is not an official ${b.key} domain', 'Mentionne « ${b.key} » sans être un domaine officiel'),
            40,
          ),
        );
        break;
      }
    }

    final path = Uri.decodeFull(uri.path + (uri.hasQuery ? '?${uri.query}' : '')).toLowerCase();
    final lures = _lureWords.where(path.contains).toList();
    if (lures.isNotEmpty) {
      ind.add(
        UrlIndicator('lure_words', LText('Lure words: ${lures.take(3).join(', ')}', 'Mots d’appât : ${lures.take(3).join(', ')}'), min(20, 7 * lures.length)),
      );
    }
    if (RegExp(r'\.(apk|exe|scr|msi|bat|js|vbs|jar|dmg|ipa)(\?|$)').hasMatch(uri.path.toLowerCase())) {
      ind.add(const UrlIndicator('executable', LText('Points to an executable/app file', 'Pointe vers un fichier exécutable/application'), 30));
    }
    if (input.length > 200) ind.add(const UrlIndicator('long', LText('Very long URL', 'URL très longue'), 5));
    if ('%'.allMatches(input).length > 10) ind.add(const UrlIndicator('encoded', LText('Heavily percent-encoded', 'Fortement encodée'), 8));

    return _result(raw, uri, decoded, ind);
  }

  UrlAnalysis _result(String raw, Uri uri, String displayHost, List<UrlIndicator> ind) {
    final host = uri.host.toLowerCase();
    final known = (host.isEmpty ? null : pack.lookupDomain(host)) ?? pack.lookupUrl(uri.toString());
    final s = min(100, ind.fold<int>(0, (a, b) => a + b.weight));
    return UrlAnalysis(
      input: raw,
      uri: uri,
      displayHost: displayHost,
      registrableDomain: registrable(host),
      indicators: ind,
      verdict: verdictFor(s, known),
      score: s,
      knownIndicator: known,
    );
  }

  UrlAnalysis _invalid(String raw) =>
      UrlAnalysis(input: raw, uri: null, displayHost: '', registrableDomain: '', indicators: const [], verdict: UrlVerdict.invalid, score: 0);

  /// Follows redirects hop by hop without downloading bodies or executing anything.
  /// Certificate validation is always on; a TLS failure ends the chain.
  static Future<List<RedirectHop>> followRedirects(Uri start, {int maxHops = 8, Duration timeout = const Duration(seconds: 8)}) async {
    final client = HttpClient()
      ..connectionTimeout = timeout
      ..userAgent = 'SentinelMobileSOC-LinkCheck/1.0';
    final hops = <RedirectHop>[];
    var current = start;
    try {
      for (var i = 0; i < maxHops; i++) {
        if (current.scheme != 'http' && current.scheme != 'https') {
          hops.add(RedirectHop(current.toString(), null, error: 'non-http scheme not followed'));
          break;
        }
        try {
          final req = await client.openUrl('GET', current).timeout(timeout);
          req.followRedirects = false;
          final res = await req.close().timeout(timeout);
          // Discard the body: only headers are inspected.
          unawaited(res.drain<void>().catchError((_) {}));
          hops.add(RedirectHop(current.toString(), res.statusCode));
          final loc = res.headers.value(HttpHeaders.locationHeader);
          if (!res.isRedirect || loc == null) break;
          current = current.resolve(loc);
        } on HandshakeException catch (e) {
          hops.add(RedirectHop(current.toString(), null, error: 'TLS: ${e.message}'));
          break;
        } on Exception catch (e) {
          hops.add(RedirectHop(current.toString(), null, error: e.toString().split('\n').first));
          break;
        }
      }
    } finally {
      client.close(force: true);
    }
    return hops;
  }
}

/// RFC 3492 decoder used only to *display* IDN labels and spot mixed scripts.
class Punycode {
  static String decodeLabel(String label) {
    if (!label.startsWith('xn--')) return label;
    try {
      return _decode(label.substring(4));
    } catch (_) {
      return label;
    }
  }

  static String _decode(String input) {
    const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700, initialBias = 72, initialN = 128;
    final output = <int>[];
    final d = input.lastIndexOf('-');
    if (d > 0) output.addAll(input.substring(0, d).codeUnits);
    var n = initialN, bias = initialBias, i = 0;
    var pos = d > 0 ? d + 1 : 0;
    int digit(int c) {
      if (c >= 48 && c <= 57) return c - 22;
      if (c >= 65 && c <= 90) return c - 65;
      if (c >= 97 && c <= 122) return c - 97;
      throw const FormatException('bad punycode');
    }

    int adapt(int delta, int numPoints, bool first) {
      delta = first ? delta ~/ damp : delta ~/ 2;
      delta += delta ~/ numPoints;
      var k = 0;
      while (delta > ((base - tMin) * tMax) ~/ 2) {
        delta ~/= base - tMin;
        k += base;
      }
      return k + (base - tMin + 1) * delta ~/ (delta + skew);
    }

    while (pos < input.length) {
      final oldi = i;
      var w = 1;
      for (var k = base; ; k += base) {
        if (pos >= input.length) throw const FormatException('truncated');
        final dg = digit(input.codeUnitAt(pos++));
        i += dg * w;
        final t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias);
        if (dg < t) break;
        w *= base - t;
      }
      bias = adapt(i - oldi, output.length + 1, oldi == 0);
      n += i ~/ (output.length + 1);
      i %= output.length + 1;
      output.insert(i, n);
      i++;
    }
    return String.fromCharCodes(output);
  }

  /// True when a label mixes Latin letters with Cyrillic or Greek letters.
  static bool isMixedScript(String label) {
    var latin = false, cyrillic = false, greek = false;
    for (final r in label.runes) {
      if ((r >= 0x41 && r <= 0x5a) || (r >= 0x61 && r <= 0x7a)) latin = true;
      if (r >= 0x0400 && r <= 0x04ff) cyrillic = true;
      if (r >= 0x0370 && r <= 0x03ff) greek = true;
    }
    return (latin && (cyrillic || greek)) || (cyrillic && greek) || (!latin && (cyrillic || greek) && label.runes.length > 1 && _confusableOnly(label));
  }

  /// All-Cyrillic labels made only of Latin look-alikes (е.g. "аррӏе").
  static bool _confusableOnly(String label) {
    const confusables = {0x0430, 0x0435, 0x043e, 0x0440, 0x0441, 0x0443, 0x0445, 0x0456, 0x0458, 0x04cf, 0x0501, 0x051b, 0x051d};
    return label.runes.every((r) => confusables.contains(r) || r == 0x2d || (r >= 0x30 && r <= 0x39));
  }
}
