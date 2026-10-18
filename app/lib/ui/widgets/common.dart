import 'dart:math';

import 'package:flutter/material.dart';

import '../../core/models.dart';
import '../../engine/scoring.dart';
import '../l10n.dart';
import '../theme.dart';

bool reduceMotion(BuildContext c) => MediaQuery.maybeOf(c)?.disableAnimations ?? false;

class Pill extends StatelessWidget {
  const Pill(this.text, this.color, {super.key, this.icon});
  final String text;
  final Color color;
  final IconData? icon;

  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
        decoration: BoxDecoration(color: color.withValues(alpha: 0.15), borderRadius: BorderRadius.circular(20), border: Border.all(color: color.withValues(alpha: 0.5))),
        child: Row(mainAxisSize: MainAxisSize.min, children: [
          if (icon != null) ...[Icon(icon, size: 12, color: color), const SizedBox(width: 4)],
          Text(text, style: TextStyle(color: color, fontSize: 11.5, fontWeight: FontWeight.w600)),
        ]),
      );
}

class SeverityPill extends StatelessWidget {
  const SeverityPill(this.s, {super.key});
  final Severity s;
  @override
  Widget build(BuildContext context) => Pill(severityLabel(context, s), SocColors.severity(s));
}

class ClassificationPill extends StatelessWidget {
  const ClassificationPill(this.c, {super.key});
  final Classification c;
  @override
  Widget build(BuildContext context) => Pill(classificationLabel(context, c), SocColors.classification(c));
}

class SectionTitle extends StatelessWidget {
  const SectionTitle(this.text, {super.key, this.trailing});
  final String text;
  final Widget? trailing;
  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.fromLTRB(4, 18, 4, 6),
        child: Row(children: [
          Expanded(
            child: Semantics(
              header: true,
              child: Text(text.toUpperCase(), style: const TextStyle(letterSpacing: 1.2, fontSize: 12, color: SocColors.muted, fontWeight: FontWeight.w700)),
            ),
          ),
          ?trailing,
        ]),
      );
}

class InfoBanner extends StatelessWidget {
  const InfoBanner(this.text, {super.key, this.color = SocColors.blue, this.icon = Icons.info_outline});
  final String text;
  final Color color;
  final IconData icon;
  @override
  Widget build(BuildContext context) => Container(
        margin: const EdgeInsets.symmetric(vertical: 6),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(color: color.withValues(alpha: 0.1), borderRadius: BorderRadius.circular(12), border: Border.all(color: color.withValues(alpha: 0.4))),
        child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Icon(icon, color: color, size: 20),
          const SizedBox(width: 10),
          Expanded(child: Text(text, style: const TextStyle(height: 1.35))),
        ]),
      );
}

/// Animated score ring. The animation is skipped when the OS asks for reduced motion.
class ScoreRing extends StatelessWidget {
  const ScoreRing({super.key, required this.score, this.size = 170});
  final SecurityScore? score;
  final double size;

  @override
  Widget build(BuildContext context) {
    final s = score;
    final color = SocColors.posture(s?.posture ?? Posture.unknown);
    final target = (s?.score ?? 0) / 100;
    final label = s == null
        ? context.tr('Not assessed yet', 'Pas encore évalué')
        : context.tr('Security score ${s.score} out of 100, posture ${postureLabel(context, s.posture)}, coverage ${(s.coverage * 100).round()} percent',
            'Score de sécurité ${s.score} sur 100, posture ${postureLabel(context, s.posture)}, couverture ${(s.coverage * 100).round()} pour cent');
    return Semantics(
      label: label,
      excludeSemantics: true,
      child: TweenAnimationBuilder<double>(
        tween: Tween(begin: 0, end: target),
        duration: reduceMotion(context) ? Duration.zero : const Duration(milliseconds: 1100),
        curve: Curves.easeOutCubic,
        builder: (context, v, _) => SizedBox(
          width: size,
          height: size,
          child: CustomPaint(
            painter: _RingPainter(v, color),
            child: Center(
              child: Column(mainAxisSize: MainAxisSize.min, children: [
                Text(s == null ? '—' : '${(v * 100).round()}', style: TextStyle(fontSize: size * 0.26, fontWeight: FontWeight.w800, color: Colors.white)),
                Text(postureLabel(context, s?.posture ?? Posture.unknown), style: TextStyle(color: color, fontWeight: FontWeight.w700)),
              ]),
            ),
          ),
        ),
      ),
    );
  }
}

class _RingPainter extends CustomPainter {
  _RingPainter(this.v, this.color);
  final double v;
  final Color color;

  @override
  void paint(Canvas canvas, Size size) {
    final c = size.center(Offset.zero);
    final r = size.width / 2 - 10;
    final bg = Paint()
      ..color = SocColors.line
      ..style = PaintingStyle.stroke
      ..strokeWidth = 12;
    canvas.drawCircle(c, r, bg);
    for (var i = 0; i < 60; i++) {
      final a = i / 60 * 2 * pi;
      final p1 = c + Offset(cos(a), sin(a)) * (r + 8);
      final p2 = c + Offset(cos(a), sin(a)) * (r + (i % 5 == 0 ? 12 : 10));
      canvas.drawLine(p1, p2, Paint()..color = SocColors.line..strokeWidth = 1);
    }
    final fg = Paint()
      ..shader = SweepGradient(colors: [color.withValues(alpha: 0.5), color], startAngle: 0, endAngle: 2 * pi, transform: const GradientRotation(-pi / 2))
          .createShader(Rect.fromCircle(center: c, radius: r))
      ..style = PaintingStyle.stroke
      ..strokeCap = StrokeCap.round
      ..strokeWidth = 12;
    canvas.drawArc(Rect.fromCircle(center: c, radius: r), -pi / 2, 2 * pi * v, false, fg);
  }

  @override
  bool shouldRepaint(_RingPainter old) => old.v != v || old.color != color;
}

/// Interactive severity distribution: tap a bar to filter.
class SeverityBars extends StatelessWidget {
  const SeverityBars({super.key, required this.findings, this.selected, this.onSelect});
  final List<Finding> findings;
  final Severity? selected;
  final ValueChanged<Severity?>? onSelect;

  @override
  Widget build(BuildContext context) {
    final counts = {for (final s in Severity.values) s: findings.where((f) => f.severity == s).length};
    final maxC = max(1, counts.values.fold<int>(0, max));
    return SizedBox(
      height: 120,
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          for (final s in Severity.values.reversed)
            Expanded(
              child: Semantics(
                button: true,
                selected: selected == s,
                label: '${severityLabel(context, s)}: ${counts[s]}',
                child: InkWell(
                  borderRadius: BorderRadius.circular(8),
                  onTap: onSelect == null ? null : () => onSelect!(selected == s ? null : s),
                  child: Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 4),
                    child: Column(mainAxisAlignment: MainAxisAlignment.end, children: [
                      Text('${counts[s]}', style: const TextStyle(fontWeight: FontWeight.w700)),
                      const SizedBox(height: 4),
                      AnimatedContainer(
                        duration: reduceMotion(context) ? Duration.zero : const Duration(milliseconds: 500),
                        height: 8 + 62 * counts[s]! / maxC,
                        decoration: BoxDecoration(
                          color: SocColors.severity(s).withValues(alpha: selected == null || selected == s ? 0.9 : 0.25),
                          borderRadius: BorderRadius.circular(6),
                        ),
                      ),
                      const SizedBox(height: 6),
                      Text(severityLabel(context, s), style: const TextStyle(fontSize: 11, color: SocColors.muted), overflow: TextOverflow.ellipsis),
                    ]),
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }
}

class FindingTile extends StatelessWidget {
  const FindingTile(this.f, {super.key, this.onTap});
  final Finding f;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) => Card(
        child: InkWell(
          borderRadius: BorderRadius.circular(14),
          onTap: onTap,
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: Row(children: [
              Container(width: 4, height: 44, decoration: BoxDecoration(color: SocColors.severity(f.severity), borderRadius: BorderRadius.circular(4))),
              const SizedBox(width: 12),
              Expanded(
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(context.lt(f.title), style: TextStyle(fontWeight: FontWeight.w600, decoration: f.isActive ? null : TextDecoration.lineThrough)),
                  const SizedBox(height: 6),
                  Wrap(spacing: 6, runSpacing: 4, children: [
                    SeverityPill(f.severity),
                    ClassificationPill(f.classification),
                    Pill(confidenceLabel(context, f.confidence), SocColors.muted),
                    if (!f.isActive) Pill(remediationLabel(context, f.status), SocColors.green),
                  ]),
                ]),
              ),
              const Icon(Icons.chevron_right, color: SocColors.muted),
            ]),
          ),
        ),
      );
}

class CoverageList extends StatelessWidget {
  const CoverageList(this.items, {super.key});
  final List<CoverageItem> items;

  @override
  Widget build(BuildContext context) => Column(
        children: [
          for (final c in items)
            ListTile(
              dense: true,
              contentPadding: EdgeInsets.zero,
              leading: Icon(
                switch (c.status) {
                  CoverageStatus.checked => Icons.check_circle,
                  CoverageStatus.error => Icons.error_outline,
                  CoverageStatus.permissionRequired => Icons.lock_outline,
                  _ => Icons.visibility_off_outlined,
                },
                color: switch (c.status) {
                  CoverageStatus.checked => SocColors.green,
                  CoverageStatus.error => SocColors.red,
                  _ => SocColors.muted,
                },
                semanticLabel: c.status.name,
              ),
              title: Text(context.lt(c.label)),
              subtitle: c.note == null ? null : Text(context.lt(c.note!), style: const TextStyle(color: SocColors.muted)),
            ),
        ],
      );
}

class EmptyState extends StatelessWidget {
  const EmptyState(this.icon, this.text, {super.key});
  final IconData icon;
  final String text;
  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.all(32),
        child: Column(children: [
          Icon(icon, size: 48, color: SocColors.muted),
          const SizedBox(height: 12),
          Text(text, textAlign: TextAlign.center, style: const TextStyle(color: SocColors.muted)),
        ]),
      );
}

/// Centers content and caps width on tablets.
class Responsive extends StatelessWidget {
  const Responsive({super.key, required this.child});
  final Widget child;
  @override
  Widget build(BuildContext context) => Center(child: ConstrainedBox(constraints: const BoxConstraints(maxWidth: 900), child: child));
}

/// Pulsing radar used while a scan runs.
class ScanRadar extends StatefulWidget {
  const ScanRadar({super.key, this.size = 150});
  final double size;
  @override
  State<ScanRadar> createState() => _ScanRadarState();
}

class _ScanRadarState extends State<ScanRadar> with SingleTickerProviderStateMixin {
  late final AnimationController _c = AnimationController(vsync: this, duration: const Duration(seconds: 2));

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (reduceMotion(context)) {
      _c.stop();
    } else if (!_c.isAnimating) {
      _c.repeat();
    }
  }

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => ExcludeSemantics(
        child: AnimatedBuilder(
          animation: _c,
          builder: (_, _) => CustomPaint(size: Size.square(widget.size), painter: _RadarPainter(_c.value)),
        ),
      );
}

class _RadarPainter extends CustomPainter {
  _RadarPainter(this.t);
  final double t;
  @override
  void paint(Canvas canvas, Size size) {
    final c = size.center(Offset.zero);
    final r = size.width / 2;
    for (var i = 1; i <= 3; i++) {
      canvas.drawCircle(c, r * i / 3, Paint()..color = SocColors.line..style = PaintingStyle.stroke);
    }
    final sweep = Paint()
      ..shader = SweepGradient(colors: [Colors.transparent, SocColors.cyan.withValues(alpha: 0.6)], stops: const [0.75, 1], transform: GradientRotation(2 * pi * t))
          .createShader(Rect.fromCircle(center: c, radius: r));
    canvas.drawCircle(c, r, sweep);
    canvas.drawCircle(c, 4, Paint()..color = SocColors.cyan);
  }

  @override
  bool shouldRepaint(_RadarPainter old) => old.t != t;
}
