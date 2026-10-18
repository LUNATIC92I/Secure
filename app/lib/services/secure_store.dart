import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:path_provider/path_provider.dart';

/// Key provider abstraction so tests can run without platform channels.
abstract class KeyProvider {
  Future<Uint8List> getOrCreateKey();
  Future<void> deleteKey();
}

/// 256-bit data key kept in Android Keystore-backed storage / iOS Keychain.
class PlatformKeyProvider implements KeyProvider {
  static const _name = 'sentinel_store_key_v1';
  final _storage = const FlutterSecureStorage(
    iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock_this_device),
  );

  @override
  Future<Uint8List> getOrCreateKey() async {
    final existing = await _storage.read(key: _name);
    if (existing != null) return base64Decode(existing);
    final rnd = Random.secure();
    final key = Uint8List.fromList(List.generate(32, (_) => rnd.nextInt(256)));
    await _storage.write(key: _name, value: base64Encode(key));
    return key;
  }

  @override
  Future<void> deleteKey() => _storage.delete(key: _name);
}

class MemoryKeyProvider implements KeyProvider {
  Uint8List? _k;
  @override
  Future<Uint8List> getOrCreateKey() async => _k ??= Uint8List.fromList(List.generate(32, (i) => i * 7 % 256));
  @override
  Future<void> deleteKey() async => _k = null;
}

/// AES-256-GCM encrypted JSON documents in the app's private directory.
/// Excluded from backups (see AndroidManifest / data_extraction_rules).
class SecureStore {
  SecureStore({required this.keys, Directory? directory}) : _configured = directory;

  final KeyProvider keys;
  final Directory? _configured;
  Directory? _dir;
  SecretKey? _key;
  final _aes = AesGcm.with256bits();

  Future<Directory> _directory() async {
    _dir ??= _configured ?? Directory('${(await getApplicationSupportDirectory()).path}/sentinel');
    if (!await _dir!.exists()) await _dir!.create(recursive: true);
    return _dir!;
  }

  Future<SecretKey> _secret() async => _key ??= SecretKey(await keys.getOrCreateKey());

  Future<File> _file(String name) async => File('${(await _directory()).path}/$name.enc');

  Future<void> write(String name, Object? json) async {
    final clear = utf8.encode(jsonEncode(json));
    final box = await _aes.encrypt(clear, secretKey: await _secret(), aad: utf8.encode(name));
    final f = await _file(name);
    final tmp = File('${f.path}.tmp');
    await tmp.writeAsBytes(box.concatenation(), flush: true);
    await tmp.rename(f.path);
  }

  /// Returns null when absent. A tampered or undecryptable file is treated as absent
  /// and reported through [onCorrupt] rather than crashing the app.
  Future<Object?> read(String name, {void Function(String)? onCorrupt}) async {
    final f = await _file(name);
    if (!await f.exists()) return null;
    try {
      final bytes = await f.readAsBytes();
      final box = SecretBox.fromConcatenation(bytes, nonceLength: _aes.nonceLength, macLength: _aes.macAlgorithm.macLength);
      final clear = await _aes.decrypt(box, secretKey: await _secret(), aad: utf8.encode(name));
      return jsonDecode(utf8.decode(clear));
    } catch (e) {
      onCorrupt?.call('$name: $e');
      return null;
    }
  }

  Future<void> delete(String name) async {
    final f = await _file(name);
    if (await f.exists()) await f.delete();
  }

  /// Deletes every stored document and the data key ("erase all my data").
  Future<void> wipe() async {
    final d = await _directory();
    if (await d.exists()) await d.delete(recursive: true);
    _dir = null;
    _key = null;
    await keys.deleteKey();
  }
}
