import 'package:flutter/material.dart';

import '../theme.dart';
import '../widgets/common.dart';

class SplashScreen extends StatelessWidget {
  const SplashScreen({super.key});

  @override
  Widget build(BuildContext context) => const Scaffold(
        body: Center(
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            ScanRadar(size: 120),
            SizedBox(height: 24),
            Text('SENTINEL', style: TextStyle(fontSize: 28, letterSpacing: 8, fontWeight: FontWeight.w800, color: Colors.white)),
            Text('MOBILE SOC', style: TextStyle(letterSpacing: 6, color: SocColors.cyan)),
          ]),
        ),
      );
}
