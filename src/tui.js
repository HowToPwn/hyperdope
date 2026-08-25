/**
 * TUI utilities for Hyperdope CLI tools (hd-ci, hd-run).
 *
 * All output goes to stderr — stdout is reserved for structured data (JSON, SARIF).
 * In non-TTY environments (piped CI, --json mode) colors are stripped automatically.
 * Respects NO_COLOR and TERM=dumb conventions.
 */

// ── Color support detection ───────────────────────────────────────────────────

export const USE_COLOR =
  process.env.NO_COLOR === undefined &&
  process.env.TERM !== 'dumb' &&
  (process.stderr.isTTY ?? false);

export const USE_TTY = process.stderr.isTTY ?? false;

function ansi(code, str) {
  return USE_COLOR ? `\x1b[${code}m${str}\x1b[0m` : str;
}

// ── Base colour helpers ───────────────────────────────────────────────────────

export const reset   = str => USE_COLOR ? `\x1b[0m${str}\x1b[0m` : str;
export const bold    = str => ansi('1', str);
export const dim     = str => ansi('2', str);
export const italic  = str => ansi('3', str);

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

// Background colours (used for badge fills)
export const bgRed     = str => ansi('41', str);
export const bgYellow  = str => ansi('43', str);
export const bgBlue    = str => ansi('44', str);
export const bgMagenta = str => ansi('45', str);
export const bgCyan    = str => ansi('46', str);

// ── Severity badge ────────────────────────────────────────────────────────────

export function severityBadge(sev) {
  const s = (sev ?? 'info').toLowerCase();
  const map = {
    critical: bold(bRed('CRITICAL')),
    high:     red('HIGH    '),
    medium:   yellow('MEDIUM  '),
    low:      cyan('LOW     '),
    info:     dim('INFO    '),
    none:     dim('NONE    '),
  };
  const label = map[s] ?? dim((s.toUpperCase()).slice(0, 8).padEnd(8));
  return `[${label}]`;
}

export function severityColor(sev, str) {
  const s = (sev ?? 'info').toLowerCase();
  const fns = {
    critical: s => bold(bRed(s)),
    high:     s => red(s),
    medium:   s => yellow(s),
    low:      s => cyan(s),
    info:     s => dim(s),
    none:     s => dim(s),
  };
  return (fns[s] ?? dim)(str);
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
      const f = cyan(FRAMES[this._frame % FRAMES.length]);
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

  succeed(text) { this._clear(); this._line(green('✓'), text); return this; }
  fail(text)    { this._clear(); this._line(red('✗'), text);   return this; }
  warn(text)    { this._clear(); this._line(yellow('⚠'), text); return this; }
  info(text)    { this._clear(); this._line(cyan('ℹ'), text);  return this; }
  skip(text)    { this._clear(); this._line(dim('○'), text);   return this; }
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

// ── Header box ────────────────────────────────────────────────────────────────

export function printHeader(title, subtitle = '') {
  const inner = 56;
  const line  = '═'.repeat(inner);
  const pad = (str, w) => {
    const visible = str.replace(/\x1b\[[0-9;]*m/g, '').length;
    return str + ' '.repeat(Math.max(0, w - visible));
  };

  gap();
  println(dim(`╔${line}╗`));
  const titleLine = bold(bCyan(' ❯ ')) + bold(title);
  println(dim('║') + ' ' + pad(titleLine, inner - 1) + dim('║'));
  if (subtitle) {
    const subLine = dim(subtitle);
    println(dim('║') + ' ' + pad(subLine, inner - 1) + dim('║'));
  }
  println(dim(`╚${line}╝`));
  gap();
}

// ── Section header ────────────────────────────────────────────────────────────

export function printSection(label) {
  gap();
  println(`  ${bold(bCyan('▸'))} ${bold(label)}`);
  println(`  ${dim('─'.repeat(50))}`);
}

// ── Pass / Fail banner ────────────────────────────────────────────────────────

export function printPassBanner(message = '') {
  const inner = 48;
  const content = `  ✓  PASS  ${message}`;
  const visible = content.replace(/\x1b\[[0-9;]*m/g, '').length;
  const rightPad = ' '.repeat(Math.max(0, inner - visible));
  gap();
  println(bGreen('  ╔' + '═'.repeat(inner) + '╗'));
  println(bGreen('  ║') + bold(bGreen(content)) + rightPad + bGreen('║'));
  println(bGreen('  ╚' + '═'.repeat(inner) + '╝'));
  gap();
}

export function printFailBanner(message = '') {
  const inner = 48;
  const content = `  ✗  FAIL  ${message}`;
  const visible = content.replace(/\x1b\[[0-9;]*m/g, '').length;
  const rightPad = ' '.repeat(Math.max(0, inner - visible));
  gap();
  println(bRed('  ╔' + '═'.repeat(inner) + '╗'));
  println(bRed('  ║') + bold(bRed(content)) + rightPad + bRed('║'));
  println(bRed('  ╚' + '═'.repeat(inner) + '╝'));
  gap();
}

// ── Key-value table ───────────────────────────────────────────────────────────

export function printKv(rows, indent = '  ') {
  const filtered = rows.filter(([, v]) => v !== null && v !== undefined && v !== '');
  if (filtered.length === 0) return;
  const maxKey = Math.max(...filtered.map(([k]) => k.length));
  for (const [k, v] of filtered) {
    println(`${indent}${dim(k.padEnd(maxKey))}  ${v}`);
  }
}

// ── Finding card ──────────────────────────────────────────────────────────────

export function printFinding(f, idx) {
  const badge = severityBadge(f.severity);
  const num   = idx !== undefined ? dim(`${String(idx + 1).padStart(2)}.`) + ' ' : '    ';
  const title = bold((f.title ?? f.summary ?? f.id ?? '').slice(0, 60));
  println(`  ${num}${badge} ${title}`);
  if (f.component) println(`         ${dim(f.component)}`);
  if (f.evidence)  println(`         ${dim(('Evidence: ' + f.evidence).slice(0, 72))}`);
}

// ── Phase summary ─────────────────────────────────────────────────────────────

/** One-liner summary string per phase result */
export function phaseSummary(name, result) {
  const m = result?.meta ?? {};
  switch (name) {
    case 'scan':
      return [
        m.packages_scanned   != null ? `${m.packages_scanned} pkgs`    : null,
        m.vulnerabilities_found      ? bold(red(`${m.vulnerabilities_found} CVEs`))  : null,
        m.secrets_found              ? bold(red(`${m.secrets_found} secrets`))        : null,
        m.hooks_found                ? yellow(`${m.hooks_found} hooks`)               : null,
      ].filter(Boolean).join(dim('  ·  ')) || 'clean';

    case 'profile': {
      const cats = result?.findings?.length ?? 0;
      return cats ? `${cats} surface categories` : 'no categories';
    }
    case 'audit': {
      const n = result?.findings?.length ?? 0;
      return n ? bold(yellow(`${n} candidate${n === 1 ? '' : 's'}`)) : dim('no candidates');
    }
    case 'confirm': {
      const n = result?.findings?.length ?? 0;
      return n ? bold(red(`${n} PoC${n === 1 ? '' : 's'} generated`)) : dim('no PoCs');
    }
    case 'assess': {
      const findings = result?.findings ?? [];
      const scores = findings.map(f => f.cvss_score).filter(s => typeof s === 'number');
      if (scores.length === 0) return 'scored';
      const max = Math.max(...scores);
      const col = max >= 9 ? bRed : max >= 7 ? red : max >= 4 ? yellow : cyan;
      return `max CVSS ${bold(col(max.toFixed(1)))}  (${findings.length} finding${findings.length === 1 ? '' : 's'})`;
    }
    case 'draft_ghsa':
      return result?.status === 'complete' ? green('advisory drafted') : dim('partial');
    case 'disclose':
      return result?.status === 'complete' ? green('disclosure package ready') : dim('partial');
    case 'verify': {
      const vs = result?.findings ?? [];
      const patched = vs.filter(v => v.verdict === 'PATCHED').length;
      const still   = vs.filter(v => v.verdict === 'STILL_VULNERABLE').length;
      const partial = vs.filter(v => v.verdict === 'PARTIAL_FIX').length;
      const parts = [
        patched ? green(`${patched} patched`) : null,
        partial ? yellow(`${partial} partial`) : null,
        still   ? red(`${still} still vulnerable`) : null,
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
