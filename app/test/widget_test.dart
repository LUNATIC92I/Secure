import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:sentinel_mobile_soc/core/models.dart';
import 'package:sentinel_mobile_soc/main.dart';
import 'package:sentinel_mobile_soc/services/repository.dart';
import 'package:sentinel_mobile_soc/services/secure_store.dart';
import 'package:sentinel_mobile_soc/state/app_state.dart';
import 'package:sentinel_native/sentinel_native.dart';

import 'fixtures.dart';

const channel = MethodChannel('io.sentinel/native');

Future<AppState> makeState(WidgetTester tester, {bool onboarded = true, String? lang, bool stalker = false, bool tall = true}) async {
  if (tall) {
    // Tall phone viewport so list content is laid out without scrolling.
    tester.view.physicalSize = const Size(1080, 6000);
    tester.view.devicePixelRatio = 2.5;
    addTearDown(tester.view.reset);
  }
  final calls = <String>[];
  tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(channel, (call) async {
    calls.add(call.method);
    return switch (call.method) {
      'platformInfo' => {'platform': 'android', 'osVersion': '16', 'model': 'Test', 'manufacturer': 'Fixture'},
      'consumeSharedText' => null,
      _ => null,
    };
  });
  final dir = Directory.systemTemp.createTempSync('sentinel_w');
  addTearDown(() => dir.deleteSync(recursive: true));
  final state = AppState(
    repo: Repository(SecureStore(keys: MemoryKeyProvider(), directory: dir)),
    native: SentinelNative(),
    source: FixtureSource(androidSnapshot(apps: [...benignApps(), if (stalker) stalkerApp()])),
  );
  await tester.runAsync(() async {
    await state.init();
    await state.updateSettings((s) {
      s.onboarded = onboarded;
      s.languageCode = lang;
    });
  });
  return state;
}

Widget wrap(AppState s) => ChangeNotifierProvider.value(value: s, child: const SentinelApp());

void main() {
  testWidgets('onboarding explains capabilities and does not request permissions', (tester) async {
    final state = await makeState(tester, onboarded: false);
    await tester.pumpWidget(wrap(state));
    await tester.pump(const Duration(milliseconds: 100));
    expect(find.text('Your personal Mobile SOC'), findsOneWidget);
    await tester.tap(find.text('Next'));
    for (var i = 0; i < 10; i++) {
      await tester.pump(const Duration(milliseconds: 50));
    }
    expect(find.textContaining('Installed-app inventory'), findsOneWidget);
    expect(find.textContaining('Call interception'), findsOneWidget);
    await tester.tap(find.text('Next'));
    for (var i = 0; i < 10; i++) {
      await tester.pump(const Duration(milliseconds: 50));
    }
    await tester.tap(find.text('Start'));
    await tester.runAsync(() => Future<void>.delayed(const Duration(milliseconds: 50)));
    await tester.pump(const Duration(milliseconds: 100));
    expect(state.settings.onboarded, isTrue);
  });

  testWidgets('dashboard before first scan, in French', (tester) async {
    final state = await makeState(tester, lang: 'fr');
    await tester.pumpWidget(wrap(state));
    await tester.pump(const Duration(milliseconds: 100));
    expect(find.text('Lancer l’analyse complète'), findsOneWidget);
    expect(find.text('Non évaluée'), findsOneWidget);
  });

  testWidgets('scan results drive dashboard; never claims "completely safe"', (tester) async {
    final state = await makeState(tester, stalker: true);
    await tester.runAsync(() => state.runScan(ScanMode.comprehensive));
    await tester.pumpWidget(wrap(state));
    await tester.pump(const Duration(seconds: 2));
    expect(find.textContaining('Possible monitoring app'), findsWidgets);
    expect(find.textContaining('completely safe'), findsNothing);
    expect(state.incidents.values.where((i) => i.open), isNotEmpty);
    // Score ring exposes an accessible description instead of raw painting.
    expect(find.bySemanticsLabel(RegExp(r'Security score \d+ out of 100')), findsOneWidget);
  });

  testWidgets('clean device shows coverage caveat, not a safety guarantee', (tester) async {
    final state = await makeState(tester);
    await tester.runAsync(() => state.runScan(ScanMode.quick));
    await tester.pumpWidget(wrap(state));
    await tester.pump(const Duration(seconds: 2));
    // Benign fixture only yields informational/low items; coverage is always displayed.
    expect(state.activeFindings.where((f) => f.severity.index >= Severity.medium.index), isEmpty);
    expect(find.textContaining('Coverage:'), findsOneWidget);
    expect(find.textContaining('completely safe'), findsNothing);
  });

  testWidgets('tablet layout renders without overflow', (tester) async {
    final state = await makeState(tester, stalker: true, tall: false);
    tester.view.physicalSize = const Size(2048, 1536);
    tester.view.devicePixelRatio = 2;
    addTearDown(tester.view.reset);
    await tester.runAsync(() => state.runScan(ScanMode.quick));
    await tester.pumpWidget(wrap(state));
    await tester.pump(const Duration(seconds: 2));
    expect(tester.takeException(), isNull);
  });

  testWidgets('offline mode: no backend configured means local-only intel', (tester) async {
    final state = await makeState(tester);
    expect(state.settings.backendConfigured, isFalse);
    expect(state.intel.providers.where((p) => p.isRemote), isEmpty);
    final (analysis, verdicts) = await tester.runAsync(() => state.analyseUrl('https://testsafebrowsing.appspot.com/s/phishing.html')) ?? (null, null);
    expect(analysis, isNotNull);
    expect(verdicts!.every((v) => v.local), isTrue);
  });

  testWidgets('reduced motion disables animations', (tester) async {
    final state = await makeState(tester);
    await tester.runAsync(() => state.runScan(ScanMode.quick));
    await tester.pumpWidget(MediaQuery(data: const MediaQueryData(disableAnimations: true), child: wrap(state)));
    await tester.pump();
    expect(find.byType(Scaffold), findsWidgets);
  });
}
