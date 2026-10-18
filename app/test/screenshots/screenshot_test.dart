// Renders real app screens with demo (synthetic) data at phone resolution for
// marketing / store screenshots. Not part of the normal suite:
//   flutter test test/screenshots --run-skipped --update-goldens
@Tags(['screenshots'])
library;

import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:sentinel_mobile_soc/core/models.dart';
import 'package:sentinel_mobile_soc/services/repository.dart';
import 'package:sentinel_mobile_soc/services/secure_store.dart';
import 'package:sentinel_mobile_soc/state/app_state.dart';
import 'package:sentinel_mobile_soc/ui/screens/call_mic_screen.dart';
import 'package:sentinel_mobile_soc/ui/screens/finding_detail_screen.dart';
import 'package:sentinel_mobile_soc/ui/screens/home_shell.dart';
import 'package:sentinel_mobile_soc/ui/screens/modules_screen.dart';
import 'package:sentinel_mobile_soc/ui/screens/onboarding_screen.dart';
import 'package:sentinel_mobile_soc/ui/screens/scan_results_screen.dart';
import 'package:sentinel_mobile_soc/ui/theme.dart';
import 'package:sentinel_native/sentinel_native.dart';

import '../fixtures.dart';

const _fonts = '/opt/sdk/flutter/bin/cache/artifacts/material_fonts';

Future<void> _loadFonts() async {
  final sdk = Platform.environment['FLUTTER_ROOT'];
  final dir = sdk != null ? '$sdk/bin/cache/artifacts/material_fonts' : _fonts;
  Future<ByteData> f(String n) async => ByteData.sublistView(await File('$dir/$n').readAsBytes());
  final roboto = FontLoader('Roboto');
  for (final n in ['Roboto-Regular.ttf', 'Roboto-Medium.ttf', 'Roboto-Bold.ttf', 'Roboto-Black.ttf', 'Roboto-Light.ttf']) {
    roboto.addFont(f(n));
  }
  await roboto.load();
  await (FontLoader('MaterialIcons')..addFont(f('MaterialIcons-Regular.otf'))).load();
}

void main() {
  late AppState state;

  setUpAll(() async {
    await _loadFonts();
  });

  setUp(() async {
    TestWidgetsFlutterBinding.ensureInitialized().defaultBinaryMessenger.setMockMethodCallHandler(
      const MethodChannel('io.sentinel/native'),
      (call) async => call.method == 'platformInfo' ? {'platform': 'android', 'osVersion': '16', 'model': 'Pixel 9', 'manufacturer': 'Google'} : null,
    );
  });

  Future<void> prepare(WidgetTester tester) async {
    tester.view.physicalSize = const Size(1080, 2400);
    tester.view.devicePixelRatio = 3;
    addTearDown(tester.view.reset);
    final dir = Directory.systemTemp.createTempSync('shots');
    addTearDown(() => dir.deleteSync(recursive: true));
    final device = cleanAndroidDevice(patch: '2026-05-05')
      ..['adbEnabled'] = true
      ..['accessibilityServices'] = [
        {'id': 'com.system.update.service/.A', 'package': 'com.system.update.service', 'isSystem': false, 'canRetrieveWindowContent': true},
      ]
      ..['deviceAdmins'] = [
        {'package': 'com.system.update.service', 'component': 'com.system.update.service/.Admin', 'isDeviceOwner': false, 'isProfileOwner': false},
      ]
      ..['notificationListeners'] = ['com.system.update.service/.N'];
    state = AppState(
      repo: Repository(SecureStore(keys: MemoryKeyProvider(), directory: dir)),
      native: SentinelNative(),
      platformOverride: DevicePlatform.android,
      source: FixtureSource(
        androidSnapshot(
          device: device,
          network: wifiNetwork(security: 'open'),
          apps: [...benignApps(), stalkerApp()],
        ),
      ),
    );
    await tester.runAsync(() async {
      await state.init();
      await state.updateSettings((s) {
        s.onboarded = true;
        s.languageCode = 'fr';
        s.dailyAssessment = false;
      });
      await state.runScan(ScanMode.comprehensive);
    });
  }

  Widget app(Widget home) => ChangeNotifierProvider.value(
    value: state,
    child: MaterialApp(
      debugShowCheckedModeBanner: false,
      theme: socTheme(),
      locale: const Locale('fr'),
      supportedLocales: const [Locale('en'), Locale('fr')],
      localizationsDelegates: const [GlobalMaterialLocalizations.delegate, GlobalWidgetsLocalizations.delegate, GlobalCupertinoLocalizations.delegate],
      home: home,
    ),
  );

  Future<void> shot(WidgetTester tester, Widget home, String name) async {
    await tester.pumpWidget(app(home));
    for (var i = 0; i < 20; i++) {
      await tester.pump(const Duration(milliseconds: 100));
    }
    await expectLater(find.byType(MaterialApp), matchesGoldenFile('goldens/$name.png'));
  }

  testWidgets('01 dashboard', (t) async {
    await prepare(t);
    await shot(t, const HomeShell(), '01_tableau_de_bord');
  });

  testWidgets('02 results', (t) async {
    await prepare(t);
    await shot(t, ScanResultsScreen(report: state.lastFullReport!), '02_resultats_analyse');
  });

  testWidgets('03 threat detail', (t) async {
    await prepare(t);
    final f = state.lastFullReport!.findings.firstWhere((f) => f.ruleId == 'AND-APP-001');
    await shot(t, FindingDetailScreen(finding: f), '03_detail_menace');
  });

  testWidgets('04 call & mic', (t) async {
    await prepare(t);
    await shot(t, const CallMicScreen(), '04_appels_micro');
  });

  testWidgets('05 modules', (t) async {
    await prepare(t);
    await shot(t, const ModulesScreen(), '05_modules');
  });

  testWidgets('06 capability matrix', (t) async {
    await prepare(t);
    await shot(
      t,
      const Scaffold(
        body: SafeArea(child: CapabilityMatrix(platform: DevicePlatform.android)),
      ),
      '06_matrice_capacites',
    );
  });
}
