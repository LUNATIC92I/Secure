// Signs a rule pack with Ed25519.
//
//   dart run tool/sign_rulepack.dart --generate            # prints a new seed + public key
//   SENTINEL_RULES_SIGNING_SEED=<base64> dart run tool/sign_rulepack.dart assets/rules/rulepack.json
//
// The seed is a secret: keep it in a password manager / CI secret, never in git.
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:cryptography/cryptography.dart';

Future<void> main(List<String> args) async {
  final algo = Ed25519();
  if (args.contains('--generate')) {
    final rnd = Random.secure();
    final seed = List<int>.generate(32, (_) => rnd.nextInt(256));
    final kp = await algo.newKeyPairFromSeed(seed);
    final pub = await kp.extractPublicKey();
    stdout.writeln('SEED (secret)  : ${base64Encode(seed)}');
    stdout.writeln('PUBLIC KEY     : ${base64Encode(pub.bytes)}');
    return;
  }
  if (args.isEmpty) {
    stderr.writeln('usage: sign_rulepack.dart <rulepack.json> | --generate');
    exit(64);
  }
  final seedB64 = Platform.environment['SENTINEL_RULES_SIGNING_SEED'];
  if (seedB64 == null) {
    stderr.writeln('SENTINEL_RULES_SIGNING_SEED is not set');
    exit(65);
  }
  final kp = await algo.newKeyPairFromSeed(base64Decode(seedB64));
  final file = File(args.first);
  final sig = await algo.sign(await file.readAsBytes(), keyPair: kp);
  await File('${file.path}.sig').writeAsString(base64Encode(sig.bytes));
  stdout.writeln('signed ${file.path} with key ${base64Encode((await kp.extractPublicKey()).bytes)}');
}
