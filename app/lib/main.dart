import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:provider/provider.dart';
import 'package:sentinel_native/sentinel_native.dart';

import 'services/background.dart';
import 'services/repository.dart';
import 'services/secure_store.dart';
import 'state/app_state.dart';
import 'ui/screens/home_shell.dart';
import 'ui/screens/onboarding_screen.dart';
import 'ui/screens/splash_screen.dart';
import 'ui/theme.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  try {
    await BackgroundScheduler.init();
  } catch (_) {
    // Scheduling is optional; the app stays fully usable without it.
  }
  final state = AppState(
    repo: Repository(SecureStore(keys: PlatformKeyProvider())),
    native: SentinelNative(),
  );
  runApp(ChangeNotifierProvider.value(value: state, child: const SentinelApp()));
  await state.init();
}

class SentinelApp extends StatelessWidget {
  const SentinelApp({super.key});

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    return MaterialApp(
      title: state.settings.brandName,
      debugShowCheckedModeBanner: false,
      theme: socTheme(),
      darkTheme: socTheme(),
      themeMode: ThemeMode.dark,
      locale: state.settings.languageCode == null ? null : Locale(state.settings.languageCode!),
      supportedLocales: const [Locale('en'), Locale('fr')],
      localizationsDelegates: const [GlobalMaterialLocalizations.delegate, GlobalWidgetsLocalizations.delegate, GlobalCupertinoLocalizations.delegate],
      home: !state.loaded
          ? const SplashScreen()
          : state.settings.onboarded
          ? const HomeShell()
          : const OnboardingScreen(),
    );
  }
}
