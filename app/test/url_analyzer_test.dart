import 'package:flutter_test/flutter_test.dart';
import 'package:sentinel_mobile_soc/detection/rule_pack.dart';
import 'package:sentinel_mobile_soc/engine/url_analyzer.dart';

import 'fixtures.dart';

void main() {
  late UrlAnalyzer a;
  setUpAll(() async => a = UrlAnalyzer(await bundledPack()));

  Set<String> ids(String url) => a.analyse(url).indicators.map((i) => i.id).toSet();

  test('legitimate brand domains are low risk', () {
    for (final u in ['https://www.paypal.com/signin', 'https://accounts.google.com/', 'https://www.impots.gouv.fr/accueil', 'https://amazon.co.uk/']) {
      final r = a.analyse(u);
      expect(r.verdict, UrlVerdict.lowRisk, reason: '$u ${r.indicators.map((i) => i.id)}');
    }
  });

  test('brand impersonation on another domain', () {
    expect(ids('https://paypal-secure-login.example.top/verify'), contains('brand_paypal'));
    expect(a.analyse('http://paypal.com.account-verify.xyz/login/confirm').verdict, isIn([UrlVerdict.highRisk, UrlVerdict.suspicious]));
  });

  test('userinfo disguise, IP host, dangerous schemes', () {
    expect(ids('http://www.apple.com@203.0.113.9/'), containsAll(['userinfo', 'ip_host']));
    expect(a.analyse('javascript:alert(1)').verdict, UrlVerdict.highRisk);
    expect(ids('data:text/html;base64,AAAA'), contains('dangerous_scheme'));
  });

  test('punycode homograph (Cyrillic "а" in apple)', () {
    final r = a.analyse('https://xn--pple-43d.com/');
    expect(r.displayHost, 'аpple.com');
    expect(r.indicators.map((i) => i.id), containsAll(['punycode', 'homograph']));
  });

  test('raw Unicode host is decoded and flagged', () {
    final r = a.analyse('https://аpple.com/');
    expect(r.indicators.map((i) => i.id), contains('homograph'));
  });

  test('known test indicators from the signed pack', () {
    expect(a.analyse('https://testsafebrowsing.appspot.com/s/phishing.html').verdict, UrlVerdict.knownMalicious);
    expect(a.analyse('https://login.phishing.sentinel-test.invalid/x').verdict, UrlVerdict.knownMalicious);
  });

  test('shorteners, executables and registrable domain', () {
    expect(ids('https://bit.ly/abc'), contains('shortener'));
    expect(ids('https://cdn.example.com/update.apk'), contains('executable'));
    expect(UrlAnalyzer.registrable('a.b.example.co.uk'), 'example.co.uk');
    expect(UrlAnalyzer.registrable('a.b.example.com'), 'example.com');
  });

  test('extracts first URL from shared text', () {
    expect(UrlAnalyzer.extractUrl('Your parcel: https://colis-suivi.example/x?id=1 thanks'), 'https://colis-suivi.example/x?id=1');
  });

  test('empty / invalid input', () {
    expect(a.analyse('').verdict, UrlVerdict.invalid);
    expect(UrlAnalyzer(RulePack.empty()).analyse('http://').verdict, UrlVerdict.invalid);
  });

  test('redirect results: cross-domain destination is scored', () {
    final base = a.analyse('https://bit.ly/x');
    final r = base.withRedirects([
      RedirectHop('https://bit.ly/x', 301),
      RedirectHop('https://paypal-login.example.top/', 200),
    ], a.analyse);
    expect(r.indicators.map((i) => i.id), containsAll(['redirect_cross_domain', 'dest_brand_paypal']));
    expect(r.score, greaterThan(base.score));
  });
}
