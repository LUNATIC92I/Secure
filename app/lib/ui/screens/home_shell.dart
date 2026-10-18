import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../state/app_state.dart';
import '../l10n.dart';
import 'dashboard_screen.dart';
import 'incidents_screen.dart';
import 'modules_screen.dart';
import 'phishing_screen.dart';
import 'scan_screen.dart';
import 'settings_screen.dart';

class HomeShell extends StatefulWidget {
  const HomeShell({super.key});
  @override
  State<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<HomeShell> {
  int _tab = 0;

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    // A link shared from another app opens the phishing scanner.
    if (state.sharedUrl != null) {
      final url = state.sharedUrl!;
      state.consumeSharedUrl();
      WidgetsBinding.instance.addPostFrameCallback((_) {
        Navigator.of(context).push(MaterialPageRoute(builder: (_) => PhishingScreen(initialUrl: url)));
      });
    }
    final openIncidents = state.incidents.values.where((i) => i.open).length;
    final pages = [
      DashboardScreen(onNavigate: (i) => setState(() => _tab = i)),
      const ScanScreen(),
      const IncidentsScreen(),
      const ModulesScreen(),
      const SettingsScreen(),
    ];
    return Scaffold(
      body: IndexedStack(index: _tab, children: pages),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _tab,
        onDestinationSelected: (i) => setState(() => _tab = i),
        destinations: [
          NavigationDestination(icon: const Icon(Icons.shield_outlined), selectedIcon: const Icon(Icons.shield), label: context.tr('SOC', 'SOC')),
          NavigationDestination(icon: const Icon(Icons.radar), label: context.tr('Scan', 'Analyse')),
          NavigationDestination(
            icon: Badge(isLabelVisible: openIncidents > 0, label: Text('$openIncidents'), child: const Icon(Icons.report_outlined)),
            label: context.tr('Incidents', 'Incidents'),
          ),
          NavigationDestination(icon: const Icon(Icons.apps), label: context.tr('Modules', 'Modules')),
          NavigationDestination(icon: const Icon(Icons.settings_outlined), label: context.tr('Settings', 'Réglages')),
        ],
      ),
    );
  }
}
