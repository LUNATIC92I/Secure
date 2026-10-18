import 'package:flutter/material.dart';

import '../core/models.dart';
import '../engine/scoring.dart';

class SocColors {
  static const black = Color(0xFF07090C);
  static const graphite = Color(0xFF12161C);
  static const graphite2 = Color(0xFF1A2029);
  static const line = Color(0xFF2A313C);
  static const silver = Color(0xFFC9D1D9);
  static const muted = Color(0xFF8B949E);
  static const blue = Color(0xFF2F81F7);
  static const cyan = Color(0xFF3DA9FC);
  static const amber = Color(0xFFF0B429);
  static const red = Color(0xFFF85149);
  static const green = Color(0xFF3FB950);
  static const purple = Color(0xFFA371F7);

  static Color severity(Severity s) => switch (s) {
        Severity.critical => red,
        Severity.high => const Color(0xFFFF7B54),
        Severity.medium => amber,
        Severity.low => cyan,
        Severity.informational => muted,
      };

  static Color posture(Posture p) => switch (p) {
        Posture.strong => green,
        Posture.fair => cyan,
        Posture.atRisk => amber,
        Posture.critical => red,
        Posture.unknown => muted,
      };

  static Color classification(Classification c) => switch (c) {
        Classification.confirmedMalicious => red,
        Classification.suspicious => amber,
        Classification.exposure => cyan,
        Classification.unverified => purple,
        Classification.informational => muted,
      };
}

ThemeData socTheme() {
  final scheme = ColorScheme.fromSeed(
    seedColor: SocColors.blue,
    brightness: Brightness.dark,
  ).copyWith(
    surface: SocColors.graphite,
    primary: SocColors.blue,
    secondary: SocColors.cyan,
    error: SocColors.red,
    onSurface: SocColors.silver,
    surfaceContainerHighest: SocColors.graphite2,
    outline: SocColors.line,
  );
  return ThemeData(
    useMaterial3: true,
    colorScheme: scheme,
    scaffoldBackgroundColor: SocColors.black,
    appBarTheme: const AppBarTheme(backgroundColor: SocColors.black, foregroundColor: SocColors.silver, elevation: 0, centerTitle: false),
    cardTheme: CardThemeData(
      color: SocColors.graphite,
      elevation: 0,
      margin: const EdgeInsets.symmetric(vertical: 6),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14), side: const BorderSide(color: SocColors.line)),
    ),
    navigationBarTheme: NavigationBarThemeData(
      backgroundColor: SocColors.graphite,
      indicatorColor: SocColors.blue.withValues(alpha: 0.25),
      labelTextStyle: WidgetStateProperty.all(const TextStyle(fontSize: 12, color: SocColors.silver)),
    ),
    dividerTheme: const DividerThemeData(color: SocColors.line, space: 1),
    chipTheme: const ChipThemeData(side: BorderSide.none),
    textTheme: Typography.whiteMountainView.apply(bodyColor: SocColors.silver, displayColor: Colors.white),
  );
}
