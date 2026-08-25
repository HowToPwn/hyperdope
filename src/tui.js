/**
 * TUI utilities for Hyperdope CLI tools (hd-ci, hd-run).
 *
 * All output goes to stderr — stdout is reserved for structured data (JSON, SARIF).
 * In non-TTY environments (piped CI, --json mode) colors are stripped automatically.
 * Respects NO_COLOR and TERM=dumb conventions.
 *
 * Brand palette derived from the Hyperdope AI logotype:
 *   hdBlue   (#6B8CE8) — "Hyper" gradient start
 *   hdPurple (#9B6BD4) — "dope"  gradient mid
 *   hdPink   (#E855A3) — "AI"    accent
 */

// ── Color support detection ───────────────────────────────────────────────────

export const USE_COLOR =
  process.env.NO_COLOR === undefined &&
  process.env.TERM    !== 'dumb'     &&
  (process.stderr.isTTY ?? false);

export const USE_TTY = process.stderr.isTTY ?? false;

/** True when the terminal supports 24-bit RGB color. */
const HAS_TRUE_COLOR =
  USE_COLOR &&
  /^(truecolor|24bit)$/i.test(process.env.COLORTERM ?? '');

// ── ANSI helpers ──────────────────────────────────────────────────────────────

function ansi(code, str) {
  return USE_COLOR ? `\x1b[${code}m${str}\x1b[0m` : str;
}

/** 24-bit RGB foreground color, falling back to a 4-bit ANSI code. */
function rgb(r, g, b, fallback4, str) {
  if (!USE_COLOR) return str;
  return HAS_TRUE_COLOR
    ? `\x1b[38;2;${r};${g};${b}m${str}\x1b[0m`
    : `\x1b[${fallback4}m${str}\x1b[0m`;
}

/** 24-bit RGB background, falling back to a 4-bit BG code. */
function rgbBg(r, g, b, fallback4, str) {
  if (!USE_COLOR) return str;
  return HAS_TRUE_COLOR
    ? `\x1b[48;2;${r};${g};${b}m${str}\x1b[0m`
    : `\x1b[${fallback4}m${str}\x1b[0m`;
}

// ── Base style helpers ────────────────────────────────────────────────────────

export const reset   = str => USE_COLOR ? `\x1b[0m${str}\x1b[0m` : str;
export const bold    = str => ansi('1', str);
export const dim     = str => ansi('2', str);
export const italic  = str => ansi('3', str);

// Standard palette (kept for backward compat and utility)
export const black   = str => ansi('30', str);
export const red     = str => ansi('31', str);
export const green   = str => ansi('32', str);
export const yellow  = str => ansi('33', str);
export const blue    = str => ansi('34', str);
export const magenta = str => ansi('35', str);
export const cyan    = str => ansi('36', str);
export const white   = str => ansi('37', str);

export const bBlack   = str => ansi('90', str);
export const bRed     = str => ansi('91', str);
export const bGreen   = str => ansi('92', str);
export const bYellow  = str => ansi('93', str);
export const bBlue    = str => ansi('94', str);
export const bMagenta = str => ansi('95', str);
export const bCyan    = str => ansi('96', str);
export const bWhite   = str => ansi('97', str);

export const bgRed     = str => ansi('41', str);
export const bgYellow  = str => ansi('43', str);
export const bgBlue    = str => ansi('44', str);
export const bgMagenta = str => ansi('45', str);
export const bgCyan    = str => ansi('46', str);

// ── Hyperdope AI brand palette ────────────────────────────────────────────────
//
//  Derived from the logotype:
//    "Hyper"  → electric blue  #6B8CE8  (107, 140, 232)
//    "dope"   → amethyst       #9B6BD4  (155, 107, 212)
//    "AI"     → hot pink       #E855A3  (232, 85,  163)
//
// 4-bit fallbacks for terminals without truecolor:
//    blue   → bright blue  (\x1b[94m)
//    purple → magenta      (\x1b[35m)
//    pink   → bright mag.  (\x1b[95m)

/** Electric blue — primary brand color ("Hyper") */
export const hdBlue   = str => rgb(107, 140, 232, '94', str);
/** Amethyst purple — secondary brand color ("dope") */
export const hdPurple = str => rgb(155, 107, 212, '35', str);
/** Hot pink — "AI" accent, CRITICAL severity, fail states */
export const hdPink   = str => rgb(232,  85, 163, '95', str);

/** Bold hot pink — for emphasis on critical items */
export const hdPinkBold = str => bold(hdPink(str));

// ── Severity badge ────────────────────────────────────────────────────────────

/**
 * Returns a fixed-width, color-coded severity badge string.
 * Width is always 11 visible characters: "[" + 8-char label + "]"
 */
export function severityBadge(sev) {
  const s = (sev ?? 'info').toLowerCase();
  const map = {
    critical: bold(hdPink('[CRITICAL]')),
    high:     bold(red('[HIGH    ]')),
    medium:   yellow('[MEDIUM  ]'),
    low:      hdBlue('[LOW     ]'),
    info:     dim('[INFO    ]'),
    ghost:    hdPurple('[GHOST   ]'),
    none:     dim('[NONE    ]'),
  };
  return map[s] ?? dim(`[${(s.toUpperCase()).slice(0, 8).padEnd(8)}]`);
}

export function severityColor(sev, str) {
  const s = (sev ?? 'info').toLowerCase();
  const fns = {
    critical: x => bold(hdPink(x)),
    high:     x => bold(red(x)),
    medium:   x => yellow(x),
    low:      x => hdBlue(x),
    ghost:    x => hdPurple(x),
    info:     x => dim(x),
    none:     x => dim(x),
  };
  return (fns[s] ?? dim)(str);
}

// ── Confidence tier badge ─────────────────────────────────────────────────────

/**
 * Visual confidence tier for a finding (1 = SPECULATIVE → 5 = CONFIRMED).
 * Derived from evidence quality, not self-reported by the LLM.
 */
export function confidenceBadge(level) {
  const n = Math.min(5, Math.max(1, level ?? 1));
  const labels = {
    5: bold(bGreen('◉◉◉◉◉')),
    4: bGreen('◉◉◉◉') + dim('◎'),
    3: yellow('◉◉◉') + dim('◎◎'),
    2: red('◉◉') + dim('◎◎◎'),
    1: dim('◉◎◎◎◎'),
  };
  const names = { 5: 'CONFIRMED', 4: 'HIGH', 3: 'MEDIUM', 2: 'LOW', 1: 'SPECULATIVE' };
  return `${labels[n]} ${dim(names[n])}`;
}

// ── Spinner ───────────────────────────────────────────────────────────────────

const FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

export class Spinner {
  constructor(text) {
    this._text  = text;
    this._frame = 0;
    this._timer = null;
  }

  start() {
    if (!USE_TTY) {
      process.stderr.write(`  ⋯  ${this._text}\n`);
      return this;
    }
    this._timer = setInterval(() => {
      const f = hdPurple(FRAMES[this._frame % FRAMES.length]);
      process.stderr.write(`\r  ${f}  ${this._text}   `);
      this._frame++;
    }, 80);
    return this;
  }

  _clear() {
    if (this._timer) { clearInterval(this._timer); this._timer = null; }
  }

  _line(icon, text) {
    const msg = text ?? this._text;
    if (USE_TTY) {
      process.stderr.write(`\r  ${icon}  ${msg}\n`);
    } else {
      process.stderr.write(`  ${icon}  ${msg}\n`);
    }
  }

  succeed(text) { this._clear(); this._line(bGreen('✓'), text);      return this; }
  fail(text)    { this._clear(); this._line(hdPink('✗'), text);      return this; }
  warn(text)    { this._clear(); this._line(yellow('⚠'), text);      return this; }
  info(text)    { this._clear(); this._line(hdBlue('ℹ'), text);      return this; }
  skip(text)    { this._clear(); this._line(dim('○'), text);         return this; }
  ghost(text)   { this._clear(); this._line(hdPurple('◌'), text);   return this; }
}

// ── Basic print helpers ───────────────────────────────────────────────────────

/** Write a line to stderr */
export function println(line = '') {
  process.stderr.write(line + '\n');
}

/** Write multiple blank lines */
export function gap(n = 1) {
  for (let i = 0; i < n; i++) process.stderr.write('\n');
}

export function printDivider(char = '─', width = 54) {
  println(dim(char.repeat(width)));
}

// ── Brand header ──────────────────────────────────────────────────────────────

/**
 * Print the Hyperdope AI branded header box.
 *
 * Visual output (truecolor terminal):
 *   ╔══════════════════════════════════════════════════════╗
 *   ║  🔮 Hyperdope AI  ·  hd-run  ·  Full Pipeline       ║
 *   ║     github.com/org/repo                              ║
 *   ╚══════════════════════════════════════════════════════╝
 *
 * "Hyperdope" is rendered with the brand gradient; "AI" in hot pink.
 */
export function printHeader(title, subtitle = '') {
  const inner = 56;
  const line  = '═'.repeat(inner);

  // Strip ANSI codes to measure visible length
  const visLen = str => str.replace(/\x1b\[[0-9;]*m/g, '').length;
  const pad    = (str, w) => str + ' '.repeat(Math.max(0, w - visLen(str)));

  // Brand logotype with gradient
  const brand =
    hdBlue('Hyper') +
    hdPurple('dope') +
    ' ' +
    bold(hdPink('AI'));

  // Prompt glyph in brand pink
  const glyph    = bold(hdPink(' ❯ '));
  const titleStr = dim('  ·  ') + bold(white(title));
  const titleLine = glyph + brand + titleStr;

  gap();
  println(dim(`╔${line}╗`));
  println(dim('║') + ' ' + pad(titleLine, inner - 1) + dim('║'));
  if (subtitle) {
    const subLine = '   ' + dim(subtitle.slice(0, inner - 4));
    println(dim('║') + pad(subLine, inner) + dim('║'));
  }
  println(dim(`╚${line}╝`));
  gap();
}

// ── Section header ────────────────────────────────────────────────────────────

export function printSection(label) {
  gap();
  println(`  ${bold(hdPurple('▸'))} ${bold(white(label))}`);
  println(`  ${dim('─'.repeat(50))}`);
}

// ── Pass / Fail banners ───────────────────────────────────────────────────────

export function printPassBanner(message = '') {
  const inner   = 48;
  const content = `  ✓  PASS  ${message}`;
  const visible = content.replace(/\x1b\[[0-9;]*m/g, '').length;
  const rpad    = ' '.repeat(Math.max(0, inner - visible));
  gap();
  println(bGreen(`  ╔${'═'.repeat(inner)}╗`));
  println(bGreen('  ║') + bold(bGreen(content)) + rpad + bGreen('║'));
  println(bGreen(`  ╚${'═'.repeat(inner)}╝`));
  gap();
}

export function printFailBanner(message = '') {
  const inner   = 48;
  const content = `  ✗  FAIL  ${message}`;
  const visible = content.replace(/\x1b\[[0-9;]*m/g, '').length;
  const rpad    = ' '.repeat(Math.max(0, inner - visible));
  gap();
  println(hdPink(`  ╔${'═'.repeat(inner)}╗`));
  println(hdPink('  ║') + bold(hdPink(content)) + rpad + hdPink('║'));
  println(hdPink(`  ╚${'═'.repeat(inner)}╝`));
  gap();
}

// ── Key-value table ───────────────────────────────────────────────────────────

export function printKv(rows, indent = '  ') {
  const filtered = rows.filter(([, v]) => v !== null && v !== undefined && v !== '');
  if (filtered.length === 0) return;
  const maxKey = Math.max(...filtered.map(([k]) => k.length));
  for (const [k, v] of filtered) {
    println(`${indent}${hdPurple('·')} ${dim(k.padEnd(maxKey))}  ${v}`);
  }
}

// ── Finding card ──────────────────────────────────────────────────────────────

export function printFinding(f, idx) {
  const badge   = severityBadge(f.severity);
  const num     = idx !== undefined ? dim(`${String(idx + 1).padStart(2)}.`) + ' ' : '    ';
  const title   = bold((f.title ?? f.summary ?? f.id ?? '').slice(0, 60));
  println(`  ${num}${badge} ${title}`);
  if (f.component)   println(`         ${dim(f.component)}`);
  if (f.confidence)  println(`         ${confidenceBadge(f.confidence)}`);
  if (f.evidence)    println(`         ${dim(('Evidence: ' + f.evidence).slice(0, 72))}`);
  if (f.blast_radius?.monthly_downloads) {
    const dl = formatDownloads(f.blast_radius.monthly_downloads);
    println(`         ${hdPink('⚡')} ${dim('Blast radius:')} ${yellow(dl + ' downloads/mo')}`);
  }
  if (f.chain_elevation) {
    println(`         ${hdPink('🔗')} ${dim('Chain: ')} ${bold(hdPink(f.chain_elevation))}`);
  }
}

/** Format large download numbers for readability (1.2M, 340K, etc.) */
export function formatDownloads(n) {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
  if (n >= 1_000)     return Math.round(n / 1_000) + 'K';
  return String(n);
}

// ── Ghost endpoint card ───────────────────────────────────────────────────────

export function printGhostFinding(f, idx) {
  const num   = idx !== undefined ? dim(`${String(idx + 1).padStart(2)}.`) + ' ' : '    ';
  println(`  ${num}${severityBadge('ghost')} ${bold(f.file ?? 'unknown file')}`);
  if (f.removed_definition) println(`         ${dim(f.removed_definition.slice(0, 72))}`);
  if (f.commit)             println(`         ${dim('Last seen: ' + f.commit.slice(0, 60))}`);
}

// ── Phase summary ─────────────────────────────────────────────────────────────

export function phaseSummary(name, result) {
  const m = result?.meta ?? {};
  switch (name) {
    case 'scan':
      return [
        m.packages_scanned   != null ? `${m.packages_scanned} pkgs`    : null,
        m.vulnerabilities_found      ? bold(red(`${m.vulnerabilities_found} CVEs`))      : null,
        m.secrets_found              ? bold(hdPink(`${m.secrets_found} secrets`))        : null,
        m.hooks_found                ? yellow(`${m.hooks_found} hooks`)                  : null,
        m.ghost_endpoints_found      ? hdPurple(`${m.ghost_endpoints_found} ghost`)      : null,
      ].filter(Boolean).join(dim('  ·  ')) || 'clean';

    case 'profile': {
      const cats = result?.findings?.length ?? 0;
      return cats ? `${cats} surface categories` : 'no categories';
    }
    case 'audit': {
      const n      = result?.findings?.length ?? 0;
      const chains = result?.chains?.length ?? 0;
      const base   = n ? bold(yellow(`${n} candidate${n === 1 ? '' : 's'}`)) : dim('no candidates');
      return chains ? base + dim('  ·  ') + hdPink(`${chains} chain${chains === 1 ? '' : 's'}`) : base;
    }
    case 'confirm': {
      const n = result?.findings?.length ?? 0;
      return n ? bold(red(`${n} PoC${n === 1 ? '' : 's'} generated`)) : dim('no PoCs');
    }
    case 'assess': {
      const findings = result?.findings ?? [];
      const scores   = findings.map(f => f.cvss_score).filter(s => typeof s === 'number');
      if (scores.length === 0) return 'scored';
      const max = Math.max(...scores);
      const col = max >= 9 ? hdPink : max >= 7 ? red : max >= 4 ? yellow : hdBlue;
      return `max CVSS ${bold(col(max.toFixed(1)))}  (${findings.length} finding${findings.length === 1 ? '' : 's'})`;
    }
    case 'draft_ghsa':
      return result?.status === 'complete' ? bGreen('advisory drafted') : dim('partial');
    case 'disclose':
      return result?.status === 'complete' ? bGreen('disclosure package ready') : dim('partial');
    case 'verify': {
      const vs      = result?.findings ?? [];
      const patched = vs.filter(v => v.verdict === 'PATCHED').length;
      const still   = vs.filter(v => v.verdict === 'STILL_VULNERABLE').length;
      const partial = vs.filter(v => v.verdict === 'PARTIAL_FIX').length;
      const parts   = [
        patched ? bGreen(`${patched} patched`)          : null,
        partial ? yellow(`${partial} partial`)           : null,
        still   ? hdPink(`${still} still vulnerable`)   : null,
      ].filter(Boolean);
      return parts.length ? parts.join(dim('  ·  ')) : dim('no results');
    }
    default:
      return result?.status ?? '';
  }
}

// ── Phase label formatting ────────────────────────────────────────────────────

export const PHASE_LABELS = {
  scan:       'Scan        ',
  profile:    'Profile     ',
  audit:      'Audit       ',
  confirm:    'Confirm     ',
  assess:     'Assess      ',
  draft_ghsa: 'Draft GHSA  ',
  disclose:   'Disclose    ',
  verify:     'Verify      ',
};

export function phaseLabel(name) {
  return dim(PHASE_LABELS[name] ?? name.padEnd(12));
}
