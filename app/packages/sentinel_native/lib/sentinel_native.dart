/// Thin Dart wrapper around the `io.sentinel/native` method channel.
///
/// All methods return raw platform observations as JSON-like maps. Callers must
/// treat a missing key or `null` value as "not observable on this device", never
/// as a negative result.
library;

import 'dart:async';

import 'package:flutter/services.dart';

class SentinelNative {
  SentinelNative({MethodChannel? channel}) : _channel = channel ?? const MethodChannel('io.sentinel/native') {
    _channel.setMethodCallHandler((call) async {
      if (call.method == 'sharedText') _shared.add(null);
    });
  }

  final MethodChannel _channel;
  final StreamController<void> _shared = StreamController<void>.broadcast();

  /// Fires when another app shares text (Android) or opens `sentinel://scan?url=` (iOS).
  Stream<void> get onSharedText => _shared.stream;

  Future<Map<String, dynamic>> _map(String method, [Map<String, dynamic>? args]) async {
    final result = await _channel.invokeMethod<Object?>(method, args);
    return _deepCast(result) as Map<String, dynamic>? ?? <String, dynamic>{};
  }

  Future<Map<String, dynamic>> platformInfo() => _map('platformInfo');
  Future<Map<String, dynamic>> deviceSnapshot() => _map('deviceSnapshot');
  Future<Map<String, dynamic>> installedApps() => _map('installedApps');
  Future<Map<String, dynamic>> networkSnapshot() => _map('networkSnapshot');
  Future<Map<String, dynamic>> analyzeApk(String path) => _map('analyzeApk', {'path': path});

  /// Opens the system document picker; returns null if the user cancels.
  Future<Map<String, dynamic>?> pickApk() async {
    final r = await _channel.invokeMethod<Object?>('pickApk');
    return _deepCast(r) as Map<String, dynamic>?;
  }

  Future<String> permissionStatus(String permission) async => await _channel.invokeMethod<String>('permissionStatus', {'permission': permission}) ?? 'denied';

  Future<String> requestPermission(String permission) async => await _channel.invokeMethod<String>('requestPermission', {'permission': permission}) ?? 'denied';

  Future<bool> openSettings(String target, {String? package}) async =>
      await _channel.invokeMethod<bool>('openSettings', {'target': target, 'package': package}) ?? false;

  Future<bool> requestUninstall(String package) async {
    try {
      return await _channel.invokeMethod<bool>('requestUninstall', {'package': package}) ?? false;
    } on PlatformException {
      return false;
    }
  }

  Future<bool> openDialer(String code) async => await _channel.invokeMethod<bool>('openDialer', {'code': code}) ?? false;

  Future<Map<String, dynamic>> bleTrackerScan({int seconds = 10}) => _map('bleTrackerScan', {'seconds': seconds});

  Future<String?> consumeSharedText() => _channel.invokeMethod<String>('consumeSharedText');

  static Object? _deepCast(Object? v) {
    if (v is Map) {
      return v.map((k, val) => MapEntry(k.toString(), _deepCast(val)));
    }
    if (v is List) return v.map(_deepCast).toList();
    return v;
  }
}
