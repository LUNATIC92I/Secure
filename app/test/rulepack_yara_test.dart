import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sentinel_mobile_soc/detection/rule_pack.dart';
import 'package:sentinel_mobile_soc/detection/yara_lite.dart';

import 'fixtures.dart';

void main() {
  group('signed rule pack', () {
    test('bundled pack verifies with the pinned key', () async {
      final pack = await bundledPack();
      expect(pack.verified, isTrue);
      expect(pack.version, greaterThanOrEqualTo(1));
      expect(pack.yaraRules, isNotEmpty);
      expect(pack.indicators.every((i) => i.test), isTrue, reason: 'bundled indicators must be marked as test fixtures');
    });

    test('tampered body is rejected', () async {
      final body = await File('assets/rules/rulepack.json').readAsString();
      final sig = await File('assets/rules/rulepack.json.sig').readAsString();
      final tampered = body.replaceFirst('"version": 1', '"version": 99');
      expect(() => RulePack.loadVerified(Uint8List.fromList(utf8.encode(tampered)), sig), throwsA(isA<RulePackException>()));
    });

    test('pack signed by an untrusted key is rejected', () async {
      final algo = Ed25519();
      final kp = await algo.newKeyPair();
      final body = utf8.encode(jsonEncode({'schema': 1, 'version': 2, 'indicators': [], 'yara': ''}));
      final sig = await algo.sign(body, keyPair: kp);
      expect(() => RulePack.loadVerified(Uint8List.fromList(body), base64Encode(sig.bytes)), throwsA(isA<RulePackException>()));
      final pub = base64Encode((await kp.extractPublicKey()).bytes);
      final ok = await RulePack.loadVerified(Uint8List.fromList(body), base64Encode(sig.bytes), trustedKeys: [pub]);
      expect(ok.version, 2);
      expect(() => RulePack.loadVerified(Uint8List.fromList(body), base64Encode(sig.bytes), trustedKeys: [pub], minimumVersion: 3),
          throwsA(isA<RulePackException>()), reason: 'rollback protection');
    });

    test('schema validation rejects malformed indicators', () {
      expect(() => packWith([{'type': 'file_sha256', 'value': 'nothex'}]), throwsA(isA<RulePackException>()));
      expect(() => packWith([{'type': 'exec', 'value': 'x'}]), throwsA(isA<RulePackException>()));
      expect(() => RulePack.parse('{"schema":2}'), throwsA(isA<RulePackException>()));
      expect(() => RulePack.parse('not json'), throwsA(isA<RulePackException>()));
    });

    test('domain lookup matches parent domains only', () {
      final pack = packWith([{'type': 'domain', 'value': 'evil.example', 'family': 'f', 'category': 'phishing', 'source': 's'}]);
      expect(pack.lookupDomain('login.evil.example'), isNotNull);
      expect(pack.lookupDomain('notevil.example'), isNull);
    });
  });

  group('YARA-lite', () {
    Uint8List b(String s) => Uint8List.fromList(utf8.encode(s));

    test('text, nocase, wide, hex wildcards and boolean conditions', () {
      final rules = YaraLite.parse(r'''
        rule A { strings: $a = "hello" nocase $b = { 41 ?? 43 } condition: $a and $b }
        rule B : tag1 { meta: severity = "low" strings: $w = "hi" wide condition: $w }
        rule C { strings: $x = "x1" $y = "y1" $z = "z1" condition: 2 of them and not $z }
        rule D { strings: $x = "x1" $y = "y1" condition: any of ($x, $y) }
      ''');
      expect(rules.map((r) => r.name), ['A', 'B', 'C', 'D']);
      expect(rules[0].match(b('xx HeLLo A-C')), isNotNull);
      expect(rules[0].match(b('hello only')), isNull);
      expect(rules[1].match(Uint8List.fromList([0x68, 0, 0x69, 0])), isNotNull);
      expect(rules[1].meta['severity'], 'low');
      expect(rules[2].match(b('x1 y1')), isNotNull);
      expect(rules[2].match(b('x1 y1 z1')), isNull);
      expect(rules[3].match(b('..y1..')), isNotNull);
    });

    test('rejects invalid rules', () {
      expect(() => YaraLite.parse('rule X { condition: \$missing }'), throwsFormatException);
      expect(() => YaraLite.parse('rule X { strings: \$a = { ZZ } condition: \$a }'), throwsFormatException);
      expect(() => YaraLite.parse('rule X { strings: \$a = "a" }'), throwsFormatException);
      expect(() => YaraLite.parse('rule X { strings: \$a = "a" condition: \$a } rule X { strings: \$a = "a" condition: \$a }'), throwsFormatException);
    });

    test('bundled EICAR rule matches the EICAR test string only', () async {
      final pack = await bundledPack();
      final eicar = pack.yaraRules.firstWhere((r) => r.name == 'EICAR_Test_File');
      expect(eicar.match(b(r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')), isNotNull);
      expect(eicar.match(b('benign content')), isNull);
    });
  });
}
