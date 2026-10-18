import 'dart:convert';
import 'dart:typed_data';

/// A small, dependency-free subset of the YARA rule language for static file analysis.
///
/// Supported: `meta`, text strings (`nocase`, `wide`, `ascii`), hex strings with `??`
/// wildcards, and conditions built from `$id`, `and`, `or`, `not`, parentheses,
/// `any|all|N of them` and `any|all|N of ($a, $b)`. Regex strings, modules and
/// offsets are intentionally unsupported so that rule evaluation stays bounded.
class YaraRule {
  YaraRule(this.name, this.tags, this.meta, this.strings, this._condition);

  final String name;
  final List<String> tags;
  final Map<String, String> meta;
  final Map<String, List<BytePattern>> strings;
  final YaraCondition _condition;

  /// Returns the identifiers of matched strings when the condition holds, else null.
  Set<String>? match(Uint8List data) {
    final hits = <String>{};
    for (final e in strings.entries) {
      if (e.value.any((p) => p.find(data))) hits.add(e.key);
    }
    return _condition.eval(hits, strings.keys.toSet()) ? hits : null;
  }
}

class YaraLite {
  static List<YaraRule> parse(String source) {
    final p = _Parser(_lex(source));
    final rules = <YaraRule>[];
    while (!p.done) {
      rules.add(p.rule());
    }
    final names = <String>{};
    for (final r in rules) {
      if (!names.add(r.name)) throw FormatException('duplicate rule ${r.name}');
    }
    return rules;
  }
}

// ---------------------------------------------------------------- patterns

class BytePattern {
  BytePattern(this.bytes, this.mask, {this.nocase = false});

  final List<int> bytes;

  /// false = wildcard byte.
  final List<bool> mask;
  final bool nocase;

  int _norm(int b) => nocase && b >= 0x41 && b <= 0x5a ? b + 32 : b;

  bool find(Uint8List data) {
    final n = bytes.length;
    if (n == 0 || data.length < n) return false;
    final firstFixed = mask.indexOf(true);
    if (firstFixed < 0) return true;
    final f = _norm(bytes[firstFixed]);
    final last = data.length - n;
    outer:
    for (var i = 0; i <= last; i++) {
      if (_norm(data[i + firstFixed]) != f) continue;
      for (var j = 0; j < n; j++) {
        if (mask[j] && _norm(data[i + j]) != _norm(bytes[j])) continue outer;
      }
      return true;
    }
    return false;
  }
}

// ---------------------------------------------------------------- conditions

abstract class YaraCondition {
  bool eval(Set<String> hits, Set<String> all);
}

class _Ref extends YaraCondition {
  _Ref(this.id);
  final String id;
  @override
  bool eval(Set<String> hits, Set<String> all) => hits.contains(id);
}

class _Not extends YaraCondition {
  _Not(this.e);
  final YaraCondition e;
  @override
  bool eval(Set<String> hits, Set<String> all) => !e.eval(hits, all);
}

class _Bin extends YaraCondition {
  _Bin(this.a, this.b, this.isAnd);
  final YaraCondition a, b;
  final bool isAnd;
  @override
  bool eval(Set<String> hits, Set<String> all) =>
      isAnd ? a.eval(hits, all) && b.eval(hits, all) : a.eval(hits, all) || b.eval(hits, all);
}

/// quantity: -1 = all, 0 = any, N otherwise. set null = them.
class _Of extends YaraCondition {
  _Of(this.quantity, this.set);
  final int quantity;
  final List<String>? set;
  @override
  bool eval(Set<String> hits, Set<String> all) {
    final ids = set ?? all.toList();
    final count = ids.where(hits.contains).length;
    if (quantity == -1) return ids.isNotEmpty && count == ids.length;
    if (quantity == 0) return count >= 1;
    return count >= quantity;
  }
}

// ---------------------------------------------------------------- lexer

enum _T { ident, string, number, hex, sym, eof }

class _Tok {
  _Tok(this.t, this.v);
  final _T t;
  final String v;
  @override
  String toString() => '$t($v)';
}

List<_Tok> _lex(String s) {
  final out = <_Tok>[];
  var i = 0;
  bool isIdent(String c) => RegExp(r'[A-Za-z0-9_$*]').hasMatch(c);
  while (i < s.length) {
    final c = s[i];
    if (c.trim().isEmpty) {
      i++;
    } else if (s.startsWith('//', i)) {
      final nl = s.indexOf('\n', i);
      i = nl < 0 ? s.length : nl;
    } else if (s.startsWith('/*', i)) {
      final end = s.indexOf('*/', i + 2);
      if (end < 0) throw const FormatException('unterminated comment');
      i = end + 2;
    } else if (c == '"') {
      final b = StringBuffer();
      i++;
      while (i < s.length && s[i] != '"') {
        if (s[i] == '\\' && i + 1 < s.length) {
          final n = s[i + 1];
          b.write(switch (n) { 'n' => '\n', 't' => '\t', '"' => '"', '\\' => '\\', _ => n });
          i += 2;
        } else {
          b.write(s[i++]);
        }
      }
      if (i >= s.length) throw const FormatException('unterminated string');
      i++;
      out.add(_Tok(_T.string, b.toString()));
    } else if (c == '{' && out.isNotEmpty && out.last.v == '=') {
      final end = s.indexOf('}', i);
      if (end < 0) throw const FormatException('unterminated hex string');
      out.add(_Tok(_T.hex, s.substring(i + 1, end)));
      i = end + 1;
    } else if ('{}():=,'.contains(c)) {
      out.add(_Tok(_T.sym, c));
      i++;
    } else if (RegExp(r'[0-9]').hasMatch(c)) {
      final st = i;
      while (i < s.length && RegExp(r'[0-9]').hasMatch(s[i])) {
        i++;
      }
      out.add(_Tok(_T.number, s.substring(st, i)));
    } else if (isIdent(c)) {
      final st = i;
      while (i < s.length && isIdent(s[i])) {
        i++;
      }
      out.add(_Tok(_T.ident, s.substring(st, i)));
    } else {
      throw FormatException('unexpected character "$c"');
    }
  }
  out.add(_Tok(_T.eof, ''));
  return out;
}

// ---------------------------------------------------------------- parser

class _Parser {
  _Parser(this.toks);
  final List<_Tok> toks;
  var pos = 0;

  bool get done => toks[pos].t == _T.eof;
  _Tok get peek => toks[pos];
  _Tok next() => toks[pos++];

  _Tok expect(_T t, [String? v]) {
    final tok = next();
    if (tok.t != t || (v != null && tok.v != v)) throw FormatException('expected ${v ?? t.name}, got ${tok.v}');
    return tok;
  }

  bool accept(String v) {
    if (peek.v == v && (peek.t == _T.ident || peek.t == _T.sym)) {
      pos++;
      return true;
    }
    return false;
  }

  YaraRule rule() {
    expect(_T.ident, 'rule');
    final name = expect(_T.ident).v;
    final tags = <String>[];
    if (accept(':')) {
      while (peek.t == _T.ident && peek.v != '{') {
        tags.add(next().v);
      }
    }
    expect(_T.sym, '{');
    final meta = <String, String>{};
    final strings = <String, List<BytePattern>>{};
    YaraCondition? cond;
    while (!accept('}')) {
      final section = expect(_T.ident).v;
      expect(_T.sym, ':');
      switch (section) {
        case 'meta':
          while (peek.t == _T.ident && toks[pos + 1].v == '=') {
            final k = next().v;
            expect(_T.sym, '=');
            meta[k] = next().v;
          }
        case 'strings':
          while (peek.t == _T.ident && peek.v.startsWith(r'$')) {
            final id = next().v;
            expect(_T.sym, '=');
            strings[id] = _stringDef();
          }
        case 'condition':
          cond = _or();
        default:
          throw FormatException('unknown section $section');
      }
    }
    if (cond == null) throw FormatException('rule $name has no condition');
    _checkRefs(cond, strings.keys.toSet(), name);
    return YaraRule(name, tags, meta, strings, cond);
  }

  void _checkRefs(YaraCondition e, Set<String> ids, String rule) {
    if (e is _Ref && !ids.contains(e.id)) throw FormatException('$rule: undefined ${e.id}');
    if (e is _Not) _checkRefs(e.e, ids, rule);
    if (e is _Bin) {
      _checkRefs(e.a, ids, rule);
      _checkRefs(e.b, ids, rule);
    }
    if (e is _Of && e.set != null) {
      for (final id in e.set!) {
        if (!ids.contains(id)) throw FormatException('$rule: undefined $id');
      }
    }
  }

  List<BytePattern> _stringDef() {
    final tok = next();
    if (tok.t == _T.hex) {
      final parts = tok.v.trim().split(RegExp(r'\s+')).where((e) => e.isNotEmpty);
      final bytes = <int>[], mask = <bool>[];
      for (final p in parts) {
        if (p == '??') {
          bytes.add(0);
          mask.add(false);
        } else if (RegExp(r'^[0-9A-Fa-f]{2}$').hasMatch(p)) {
          bytes.add(int.parse(p, radix: 16));
          mask.add(true);
        } else {
          throw FormatException('bad hex token $p');
        }
      }
      if (bytes.isEmpty) throw const FormatException('empty hex string');
      return [BytePattern(bytes, mask)];
    }
    if (tok.t != _T.string) throw FormatException('expected string, got ${tok.v}');
    if (tok.v.isEmpty) throw const FormatException('empty string');
    var nocase = false, wide = false, ascii = false;
    while (peek.t == _T.ident && const {'nocase', 'wide', 'ascii'}.contains(peek.v)) {
      switch (next().v) {
        case 'nocase':
          nocase = true;
        case 'wide':
          wide = true;
        case 'ascii':
          ascii = true;
      }
    }
    final raw = utf8.encode(tok.v);
    final norm = nocase ? raw.map((b) => b >= 0x41 && b <= 0x5a ? b + 32 : b).toList() : raw;
    final out = <BytePattern>[];
    if (!wide || ascii) out.add(BytePattern(norm, List.filled(norm.length, true), nocase: nocase));
    if (wide) {
      final w = <int>[for (final b in norm) ...[b, 0]];
      out.add(BytePattern(w, List.filled(w.length, true), nocase: nocase));
    }
    return out;
  }

  YaraCondition _or() {
    var e = _and();
    while (accept('or')) {
      e = _Bin(e, _and(), false);
    }
    return e;
  }

  YaraCondition _and() {
    var e = _not();
    while (accept('and')) {
      e = _Bin(e, _not(), true);
    }
    return e;
  }

  YaraCondition _not() => accept('not') ? _Not(_not()) : _primary();

  YaraCondition _primary() {
    if (accept('(')) {
      final e = _or();
      expect(_T.sym, ')');
      return e;
    }
    final tok = peek;
    int? quantity;
    if (tok.t == _T.ident && tok.v == 'any') quantity = 0;
    if (tok.t == _T.ident && tok.v == 'all') quantity = -1;
    if (tok.t == _T.number) quantity = int.parse(tok.v);
    if (quantity != null) {
      next();
      expect(_T.ident, 'of');
      if (accept('them')) return _Of(quantity, null);
      expect(_T.sym, '(');
      final ids = <String>[expect(_T.ident).v];
      while (accept(',')) {
        ids.add(expect(_T.ident).v);
      }
      expect(_T.sym, ')');
      return _Of(quantity, ids);
    }
    if (tok.t == _T.ident && tok.v.startsWith(r'$')) {
      next();
      return _Ref(tok.v);
    }
    throw FormatException('unexpected token ${tok.v} in condition');
  }
}
