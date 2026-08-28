import { readFileSync, existsSync, readdirSync, openSync, fstatSync, closeSync, constants, statSync } from 'fs';
import { join, resolve, relative, isAbsolute, extname }    from 'path';
import { execSync }                                        from 'child_process';

const OSV_BATCH_URL  = 'https://api.osv.dev/v1/querybatch';
const OSV_BATCH_SIZE = 500;

// FIX PHẦN 10: Size limit for lockfile JSON parsing — OOM protection
const MAX_LOCKFILE_BYTES = 20 * 1024 * 1024; // 20 MB

function safeReadJson(filePath) {
  try {
    const { size } = statSync(filePath);
    if (size > MAX_LOCKFILE_BYTES) {
      process.stderr.write(
        `[hd_scan] Skipping ${filePath} — size ${(size / 1024 / 1024).toFixed(1)} MB exceeds ${MAX_LOCKFILE_BYTES / 1024 / 1024} MB limit\n`
      );
      return null;
    }
    return JSON.parse(readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

// ── Lockfile parsers ─────────────────────────────────────────────────────────

function stripSemverRange(v) {
  return (v ?? '').replace(/^[\^~>=<]+/, '').trim();
}

function parsePackageLock(dir) {
  const lockPath = join(dir, 'package-lock.json');
  if (!existsSync(lockPath)) return [];
  const data = safeReadJson(lockPath);
  if (!data) return [];
  const pkgs = [];

  if (data.packages) {
    for (const [key, entry] of Object.entries(data.packages)) {
      if (!key || key === '') continue;
      const name = key.replace(/^node_modules\//, '');
      if (name && entry.version) pkgs.push({ name, version: entry.version, ecosystem: 'npm' });
    }
    return pkgs;
  }

  if (data.dependencies) {
    const walk = (deps) => {
      for (const [name, entry] of Object.entries(deps)) {
        if (entry.version) pkgs.push({ name, version: entry.version, ecosystem: 'npm' });
        if (entry.dependencies) walk(entry.dependencies);
      }
    };
    walk(data.dependencies);
  }
  return pkgs;
}

function parsePackageJson(dir) {
  const pkgPath = join(dir, 'package.json');
  if (!existsSync(pkgPath)) return [];
  const data = safeReadJson(pkgPath);
  if (!data) return [];
  const pkgs = [];
  for (const section of ['dependencies', 'devDependencies', 'peerDependencies']) {
    if (!data[section]) continue;
    for (const [name, ver] of Object.entries(data[section])) {
      const version = stripSemverRange(ver);
      if (name && version) pkgs.push({ name, version, ecosystem: 'npm' });
    }
  }
  return pkgs;
}

function parseRequirementsTxt(dir) {
  const reqPath = join(dir, 'requirements.txt');
  if (!existsSync(reqPath)) return [];
  const lines = readFileSync(reqPath, 'utf8').split('\n');
  const pkgs = [];
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith('-r') || line.startsWith('-c')) continue;
    const match = line.match(/^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.\-+]+)/);
    if (match) pkgs.push({ name: match[1], version: match[2], ecosystem: 'PyPI' });
  }
  return pkgs;
}

/** Parse poetry.lock (TOML [[package]] blocks) */
function parsePoetryLock(dir) {
  const lockPath = join(dir, 'poetry.lock');
  if (!existsSync(lockPath)) return [];
  const content = readFileSync(lockPath, 'utf8');
  const pkgs = [];
  for (const block of content.split('[[package]]').slice(1)) {
    const name    = block.match(/^name\s*=\s*"([^"]+)"/m)?.[1];
    const version = block.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
    if (name && version) pkgs.push({ name, version, ecosystem: 'PyPI' });
  }
  return pkgs;
}

/** Parse Pipfile.lock */
function parsePipfileLock(dir) {
  const lockPath = join(dir, 'Pipfile.lock');
  if (!existsSync(lockPath)) return [];
  try {
    const data = safeReadJson(lockPath);
    if (!data) return [];
    const pkgs = [];
    for (const section of ['default', 'develop']) {
      if (!data[section]) continue;
      for (const [name, entry] of Object.entries(data[section])) {
        const version = (entry.version ?? '').replace('==', '');
        if (name && version) pkgs.push({ name, version, ecosystem: 'PyPI' });
      }
    }
    return pkgs;
  } catch { return []; }
}

function parseGoMod(dir) {
  const modPath = join(dir, 'go.mod');
  if (!existsSync(modPath)) return [];
  const content = readFileSync(modPath, 'utf8');
  const pkgs = [];

  const single = content.matchAll(/^require\s+(\S+)\s+(v\S+)/gm);
  for (const m of single) {
    pkgs.push({ name: m[1], version: m[2].replace(/^v/, ''), ecosystem: 'Go' });
  }

  const blockMatch = content.match(/require\s*\(([^)]+)\)/s);
  if (blockMatch) {
    for (const line of blockMatch[1].split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('//')) continue;
      const parts = trimmed.split(/\s+/);
      if (parts.length >= 2) {
        pkgs.push({ name: parts[0], version: parts[1].replace(/^v/, ''), ecosystem: 'Go' });
      }
    }
  }
  return pkgs;
}

/** Parse Cargo.lock (TOML [[package]] blocks) */
function parseCargoLock(dir) {
  const lockPath = join(dir, 'Cargo.lock');
  if (!existsSync(lockPath)) return [];
  const content = readFileSync(lockPath, 'utf8');
  const pkgs = [];
  for (const block of content.split('[[package]]').slice(1)) {
    const name    = block.match(/^name\s*=\s*"([^"]+)"/m)?.[1];
    const version = block.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
    if (name && version) pkgs.push({ name, version, ecosystem: 'crates.io' });
  }
  return pkgs;
}

// ── OSV API ──────────────────────────────────────────────────────────────────

function getFixedIn(vuln) {
  for (const aff of (vuln.affected ?? [])) {
    for (const range of (aff.ranges ?? [])) {
      for (const ev of (range.events ?? [])) {
        if (ev.fixed) return ev.fixed;
      }
    }
  }
  return null;
}

function getSeverity(vuln) {
  if (vuln.severity?.length > 0) return vuln.severity[0].score ?? vuln.severity[0].type ?? 'UNKNOWN';
  if (vuln.database_specific?.severity) return vuln.database_specific.severity;
  return 'UNKNOWN';
}

async function osvBatch(queries) {
  if (queries.length === 0) return [];
  const results = [];
  for (let i = 0; i < queries.length; i += OSV_BATCH_SIZE) {
    const batch = queries.slice(i, i + OSV_BATCH_SIZE);
    const resp  = await fetch(OSV_BATCH_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ queries: batch }),
    });
    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`OSV API error (${resp.status}): ${text}`);
    }
    const data = await resp.json();
    results.push(...(data.results ?? []));
  }
  return results;
}

// ── npm postinstall hook detection ───────────────────────────────────────────

const HOOK_NAMES = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublishOnly', 'prepack'];
const SHELL_DOWNLOAD_RE = /\b(curl|wget|bash|sh\s+-[ce]|node\s+-e|fetch\b|powershell\b)/i;

function detectPostinstallHooks(dir) {
  const pkgPath = join(dir, 'package.json');
  if (!existsSync(pkgPath)) return [];
  let data;
  try { data = JSON.parse(readFileSync(pkgPath, 'utf8')); } catch { return []; }

  const hooks = [];
  const scripts = data.scripts ?? {};
  for (const hook of HOOK_NAMES) {
    const cmd = scripts[hook];
    if (!cmd) continue;
    const risk = SHELL_DOWNLOAD_RE.test(cmd) ? 'high' : 'medium';
    hooks.push({ hook, cmd, risk, package: data.name ?? '(root)', ecosystem: 'npm' });
  }
  return hooks;
}

// ── Secret detection ─────────────────────────────────────────────────────────

/**
 * Lightweight secret detection — scan a small set of high-value files in the
 * project root for hardcoded credentials. Not a full recursive scan; the intent
 * is to catch the most common developer mistakes (committed .env, hardcoded keys)
 * without the performance cost of scanning all source files.
 */

const SECRET_PATTERNS = [
  { type: 'AWS Access Key ID',       re: /AKIA[0-9A-Z]{16}/g },
  { type: 'GitHub Personal Access Token (classic)', re: /ghp_[A-Za-z0-9]{36}/g },
  { type: 'GitHub OAuth Token',      re: /gho_[A-Za-z0-9]{36}/g },
  { type: 'GitHub Actions Token',    re: /ghs_[A-Za-z0-9]{36}/g },
  { type: 'Anthropic API Key',       re: /sk-ant-api03-[A-Za-z0-9_-]{93}/g },
  { type: 'OpenAI API Key',          re: /sk-[A-Za-z0-9]{48}/g },
  { type: 'Slack Bot Token',         re: /xoxb-[0-9A-Za-z-]+/g },
  { type: 'Slack User Token',        re: /xoxp-[0-9A-Za-z-]+/g },
  { type: 'Google API Key',          re: /AIza[0-9A-Za-z_\-]{35}/g },
  { type: 'Stripe Live Secret Key',  re: /sk_live_[A-Za-z0-9]{24}/g },
  { type: 'PEM Private Key Block',   re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY(?:----- ?|\n)/g },
  {
    type: 'Hardcoded credential assignment',
    re: /(?:password|passwd|secret|api[_-]?key|auth[_-]?token)\s*[:=]\s*["'][A-Za-z0-9!@#$%^&*_\-+=]{8,}["']/gi,
  },
];

// Files scanned at the root level + common config locations
const SCAN_FILES = [
  '.env', '.env.local', '.env.production', '.env.development',
  'config.yaml', 'config.yml', 'config.json', 'secrets.yaml', 'secrets.yml',
  'docker-compose.yml', 'docker-compose.yaml',
  'terraform.tfvars', '.tfvars',
];

// Extensions scanned one level deep (not recursive, avoiding node_modules)
const SCAN_EXTENSIONS = new Set(['.env', '.yaml', '.yml', '.json', '.toml']);
const SKIP_DIRS       = new Set([
  'node_modules', '.git', 'dist', 'build', '.next',
  '__pycache__', 'vendor', '.cache', '.hyperdope',
]);

/** Return a redacted preview of a match — show prefix/suffix but mask the middle. */
function redactMatch(match) {
  if (match.length <= 8) return '[REDACTED]';
  return `${match.slice(0, 4)}...[REDACTED]...${match.slice(-4)}`;
}

function detectSecrets(dir) {
  const secrets = [];
  const checked = new Set();

  function scanContent(filePath, content) {
    if (checked.has(filePath)) return;
    checked.add(filePath);

    for (const { type, re } of SECRET_PATTERNS) {
      re.lastIndex = 0; // reset stateful regex
      let m;
      while ((m = re.exec(content)) !== null) {
        // Skip lines that look like comments or env-var references (${VAR})
        const lineStart = content.lastIndexOf('\n', m.index) + 1;
        const line      = content.slice(lineStart, content.indexOf('\n', m.index)).trimStart();
        if (line.startsWith('#') || line.startsWith('//') || m[0].includes('${')) continue;

        const lineNum = content.slice(0, m.index).split('\n').length;
        secrets.push({
          id:            `SECRET-${String(secrets.length + 1).padStart(3, '0')}`,
          type,
          file:          filePath.replace(dir + '/', '').replace(dir + '\\', ''),
          line:          lineNum,
          match_preview: redactMatch(m[0]),
          severity:      type.includes('Private Key') ? 'critical' : 'high',
        });
      }
    }
  }

  // Scan explicit high-value filenames
  // Open via fd with O_NOFOLLOW to atomically prevent symlink following (closes TOCTOU race)
  for (const name of SCAN_FILES) {
    const fp = join(dir, name);
    let fd;
    try {
      fd = openSync(fp, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      if (!fstatSync(fd).isFile()) continue;
      scanContent(fp, readFileSync(fd, 'utf8'));
    } catch { /* file removed, unreadable, or symlink (ELOOP on O_NOFOLLOW) */ }
    finally { if (fd !== undefined) try { closeSync(fd); } catch {} }
  }

  // Scan one level deep for files with sensitive extensions (avoid recursion into node_modules)
  //
  // Open each file via fd with O_NOFOLLOW, then read from the fd.
  // This closes the TOCTOU window: if the file is swapped for a symlink
  // between readdirSync and the open call, O_NOFOLLOW causes ELOOP and we
  // skip it. Reading from the fd (not the path) then operates on the file
  // we actually opened, not whatever path currently names.
  try {
    for (const entry of readdirSync(dir)) {
      if (SKIP_DIRS.has(entry)) continue;
      if (!SCAN_EXTENSIONS.has(extname(entry).toLowerCase())) continue;
      const fp = join(dir, entry);
      let fd;
      try {
        fd = openSync(fp, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
        if (!fstatSync(fd).isFile()) continue;
        scanContent(fp, readFileSync(fd, 'utf8'));
      } catch { /* file removed, unreadable, or symlink (ELOOP on O_NOFOLLOW) */ }
      finally { if (fd !== undefined) try { closeSync(fd); } catch {} }
    }
  } catch { /* unreadable dir */ }

  return secrets;
}

// ── Ghost Endpoint Discovery ─────────────────────────────────────────────────
//
// Parse `git log -p` for removed route/handler definitions — routes that existed
// in the git history but are no longer in the current codebase. On multi-node or
// rolling deployments, old instances may still serve them.
//
// This is a niche differentiating feature: standard SAST tools only see current
// code; ghost endpoint discovery surfaces the historical attack surface.

const GHOST_ROUTE_RE = [
  // Express / Koa / Fastify / Connect — any HTTP verb
  /^-\s*(?:app|router|server|express|fastify|koa)\s*\.\s*(get|post|put|delete|patch|head|options)\s*\(/i,
  // NestJS / TypeScript decorators
  /^-\s*@(Get|Post|Put|Delete|Patch|Options|Head)\s*\(/,
  // Flask Python routes
  /^-\s*@\w+\.route\s*\(/i,
  /^-\s*@bp\.route\s*\(/i,
  // Django urls.py
  /^-\s*(?:url|path|re_path)\s*\(\s*r?['"]/i,
  // Go net/http or chi/gorilla
  /^-.*\b(?:mux|r|router)\s*\.\s*Handle(?:Func)?\s*\(/i,
  // Rails routes.rb
  /^-\s*(?:get|post|put|delete|patch|resources?|namespace|mount)\s+['"`]/i,
  // FastAPI Python
  /^-\s*@(?:app|router)\s*\.\s*(?:get|post|put|delete|patch|options)\s*\(/i,
  // Hapi.js
  /^-\s*server\.route\s*\(\s*\{/i,
];

/**
 * Analyse git history for route definitions removed from source files.
 * Returns an array of ghost endpoint objects (capped at 25 to avoid noise).
 *
 * @param {string} dir — resolved absolute project directory
 * @returns {{ file: string, removed_definition: string, commit: string }[]}
 */
function detectGhostEndpoints(dir) {
  // 1. Verify we're inside a git repository
  try {
    execSync('git rev-parse --git-dir', { cwd: dir, stdio: 'ignore', timeout: 3000 });
  } catch {
    return [];
  }

  // 2. Pull diff of deleted/modified source lines from the last year
  let diff = '';
  try {
    diff = execSync(
      'git log --diff-filter=MD -p --since="1 year ago" ' +
      '-- "*.js" "*.ts" "*.jsx" "*.tsx" "*.py" "*.go" "*.rb" "*.java" "*.php"',
      { cwd: dir, encoding: 'utf8', timeout: 8000, maxBuffer: 3 * 1024 * 1024 },
    );
  } catch {
    return [];
  }

  const found  = new Map();      // key → finding object
  let currentFile   = '';
  let currentCommit = '';

  for (const line of diff.split('\n')) {
    // git log one-liner: <hash> <subject>
    if (/^[0-9a-f]{7,40} /.test(line)) {
      currentCommit = line.trim().slice(0, 72);
    }
    // diff header: --- a/<path>
    const fileMatch = line.match(/^--- a\/(.+)$/);
    if (fileMatch) { currentFile = fileMatch[1]; continue; }

    // Skip additions and context lines — we only care about removals (-)
    if (!line.startsWith('-')) continue;

    for (const re of GHOST_ROUTE_RE) {
      if (re.test(line)) {
        const key = `${currentFile}::${line.trim().slice(0, 80)}`;
        if (!found.has(key)) {
          found.set(key, {
            file:               currentFile,
            removed_definition: line.trim().slice(0, 120),
            commit:             currentCommit,
          });
        }
        break;
      }
    }
  }

  return [...found.values()].slice(0, 25);
}

// ── Blast Radius via Registry APIs ───────────────────────────────────────────
//
// For CVE findings, we fetch monthly download counts from npm/PyPI to surface
// "this package has 12.3M downloads/month" in the report. This contextualises
// severity — a vuln in a massively-used package is more urgent to patch even
// if its CVSS score is identical to one in a niche library.
//
// APIs:
//   npm  — https://api.npmjs.org/downloads/point/last-month/<pkg>  (free, no auth)
//   PyPI — https://pypistats.org/api/packages/<pkg>/recent         (free, no auth)

const BLAST_TIER_THRESHOLDS = [
  { tier: 'massive', min: 1_000_000 },
  { tier: 'high',    min: 100_000 },
  { tier: 'medium',  min: 10_000 },
  { tier: 'low',     min: 0 },
];

function blastTier(n) {
  for (const { tier, min } of BLAST_TIER_THRESHOLDS) {
    if (n >= min) return tier;
  }
  return 'low';
}

/**
 * Fetch monthly download count for one package from npm or PyPI.
 * Returns null on any error or timeout (3 s).
 *
 * @param {string} name
 * @param {'npm'|'PyPI'} ecosystem
 * @returns {Promise<{monthly_downloads:number,tier:string,source:string}|null>}
 */
async function fetchBlastRadius(name, ecosystem) {
  // Validate name is a safe package identifier before embedding in URL
  if (!/^(@[a-zA-Z0-9_-]+\/)?[a-zA-Z0-9._-]+$/.test(name)) return null;
  try {
    const signal = AbortSignal.timeout(3000);
    let url, extract;

    if (ecosystem === 'npm') {
      url     = `https://api.npmjs.org/downloads/point/last-month/${encodeURIComponent(name)}`;
      extract = d => d.downloads;
    } else if (ecosystem === 'PyPI') {
      url     = `https://pypistats.org/api/packages/${encodeURIComponent(name.toLowerCase())}/recent`;
      extract = d => d.data?.last_month;
    } else {
      return null;
    }

    const resp = await fetch(url, { signal });
    if (!resp.ok) return null;
    const data  = await resp.json();
    const count = extract(data);
    if (typeof count !== 'number' || count < 0) return null;
    return { monthly_downloads: count, tier: blastTier(count), source: ecosystem };
  } catch {
    return null;
  }
}

// ── Dependency Confusion Detection ───────────────────────────────────────────
//
// Check whether any npm package has a name that looks like an internal private
// package (common pattern: no scope prefix + internal/private/corp suffix) and
// may be squattable on the public registry.
//
// This is a purely static, heuristic check — no network needed.

const INTERNAL_PACKAGE_RE = /(?:^|-|_)(?:internal|private|corp|local|intranet|infra|platform)(?:$|-|_)/i;
const SCOPED_RE            = /^@/;

/**
 * Detect packages that may be vulnerable to dependency confusion attacks.
 * @param {{ name:string, ecosystem:string }[]} packages
 * @returns {{ name:string, ecosystem:string, reason:string }[]}
 */
function detectDependencyConfusion(packages) {
  const suspects = [];
  for (const p of packages) {
    if (p.ecosystem !== 'npm')  continue;
    if (SCOPED_RE.test(p.name)) continue;       // scoped packages are OK
    if (INTERNAL_PACKAGE_RE.test(p.name)) {
      suspects.push({
        name:      p.name,
        ecosystem: p.ecosystem,
        reason:    `Name "${p.name}" contains internal/private naming pattern — may be squattable on npm`,
      });
    }
  }
  return suspects.slice(0, 10);   // cap to 10 to avoid noise on large monorepos
}

// ── SBOM lite ────────────────────────────────────────────────────────────────

/** Generate a minimal SBOM-lite listing all resolved packages. */
function buildSbom(packages, dir) {
  return {
    sbom_format:  'hyperdope-sbom-lite-1.0',
    generated_at: new Date().toISOString(),
    target:       dir,
    components:   packages.map(p => ({
      type:      'library',
      name:      p.name,
      version:   p.version,
      ecosystem: p.ecosystem,
      purl:      `pkg:${p.ecosystem.toLowerCase()}/${encodeURIComponent(p.name)}@${p.version}`,
    })),
    total_components: packages.length,
  };
}

// ── Main ─────────────────────────────────────────────────────────────────────

export async function runScan({ target, context = {} }) {
  const dir = resolve(target);
  // FIX LOW-1: CWE-22 — Enforce target path stays within cwd
  const cwd = process.cwd();
  const rel = relative(cwd, dir);
  if (rel.startsWith('..') || isAbsolute(rel)) {
    throw new Error(`[hd_scan] target path must be within the working directory: "${target}"`);
  }

  // ── 1. Collect packages from all supported lockfiles ─────────────────────
  let packages = [];
  const ecosystems = new Set();

  // npm (prefer lockfile → package.json)
  const npmLock = parsePackageLock(dir);
  if (npmLock.length > 0) {
    packages.push(...npmLock);
    ecosystems.add('npm');
  } else {
    const npmPkg = parsePackageJson(dir);
    if (npmPkg.length > 0) { packages.push(...npmPkg); ecosystems.add('npm'); }
  }

  // Python (requirements.txt → poetry.lock → Pipfile.lock)
  const pyReq = parseRequirementsTxt(dir);
  if (pyReq.length > 0) { packages.push(...pyReq); ecosystems.add('PyPI'); }
  else {
    const pyPoetry = parsePoetryLock(dir);
    if (pyPoetry.length > 0) { packages.push(...pyPoetry); ecosystems.add('PyPI'); }
    else {
      const pyPipfile = parsePipfileLock(dir);
      if (pyPipfile.length > 0) { packages.push(...pyPipfile); ecosystems.add('PyPI'); }
    }
  }

  // Go
  const goPkgs = parseGoMod(dir);
  if (goPkgs.length > 0) { packages.push(...goPkgs); ecosystems.add('Go'); }

  // Rust
  const cargoPkgs = parseCargoLock(dir);
  if (cargoPkgs.length > 0) { packages.push(...cargoPkgs); ecosystems.add('crates.io'); }

  // ── 2. Ghost endpoint discovery (git history) ───────────────────────────
  const ghostRaw     = detectGhostEndpoints(dir);
  const ghostFindings = ghostRaw.map((g, i) => ({
    id:                 `GHOST-${String(i + 1).padStart(3, '0')}`,
    osv_id:             null,
    aliases:            [],
    package:            g.file,
    version:            'removed',
    ecosystem:          'ghost-endpoint',
    summary:            `Removed route definition — may still be live on older deployments: ${g.removed_definition.slice(0, 80)}`,
    severity:           'LOW',
    fixed_in:           'verify old deployments are decommissioned or route is intentionally removed',
    references:         [
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information',
    ],
    file:               g.file,
    removed_definition: g.removed_definition,
    commit:             g.commit,
    ghost:              true,
  }));

  // ── 4. Postinstall hook detection (npm) ──────────────────────────────────
  const hookFindings = detectPostinstallHooks(dir).map((h, i) => ({
    id:        `HOOK-${String(i + 1).padStart(3, '0')}`,
    osv_id:    null,
    aliases:   [],
    package:   `${h.package} (${h.hook} hook)`,
    version:   'n/a',
    ecosystem: h.ecosystem,
    summary:   `Lifecycle hook "${h.hook}" executes: ${h.cmd.slice(0, 120)}`,
    severity:  h.risk.toUpperCase(),
    fixed_in:  'manual review required',
    references: [],
    hook_type: h.hook,
    hook_cmd:  h.cmd,
  }));

  // ── 3. Secret detection ──────────────────────────────────────────────────
  const secretFindings = detectSecrets(dir).map(s => ({
    id:          s.id,
    osv_id:      null,
    aliases:     [],
    package:     s.file,
    version:     `line ${s.line}`,
    ecosystem:   'secret',
    summary:     `Hardcoded ${s.type} detected`,
    severity:    s.severity.toUpperCase(),
    fixed_in:    'rotate credential + remove from repository',
    references:  ['https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository'],
    secret_type: s.type,
    file:        s.file,
    match_preview: s.match_preview,
  }));

  // ── 5. Dependency confusion detection ────────────────────────────────────
  const confusionSuspects = detectDependencyConfusion(packages);
  const confusionFindings = confusionSuspects.map((c, i) => ({
    id:        `CONFUSE-${String(i + 1).padStart(3, '0')}`,
    osv_id:    null,
    aliases:   [],
    package:   c.name,
    version:   'n/a',
    ecosystem: c.ecosystem,
    summary:   c.reason,
    severity:  'MEDIUM',
    fixed_in:  'scope the package name (@yourorg/package-name) or publish a placeholder to the public registry',
    references: [
      'https://dhiyaneshgeek.github.io/web/security/2021/09/04/dependency-confusion/',
      'https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610',
    ],
  }));

  // ── 6. No packages + no secrets + no hooks ───────────────────────────────
  if (packages.length === 0 && hookFindings.length === 0 && secretFindings.length === 0
      && ghostFindings.length === 0) {
    return {
      phase:    'scan',
      status:   'partial',
      findings: [],
      context:  { ...context, scan: JSON.stringify({ error: 'No supported lockfiles found', target: dir }) },
      raw:      `No lockfiles found in ${dir}. Supported: package-lock.json, package.json, requirements.txt, poetry.lock, Pipfile.lock, go.mod, Cargo.lock`,
      meta:     { packages_scanned: 0, vulnerabilities_found: 0, secrets_found: 0, hooks_found: 0, ghost_endpoints_found: 0, confusion_suspects: 0, ecosystems: [], target: dir },
    };
  }

  // ── 7. Deduplicate packages ───────────────────────────────────────────────
  const seen = new Set();
  packages = packages.filter(p => {
    const key = `${p.ecosystem}:${p.name}@${p.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // ── 8. SBOM generation ────────────────────────────────────────────────────
  const sbom = buildSbom(packages, dir);

  // ── 9. OSV vulnerability scan ─────────────────────────────────────────────
  let osvFindings = [];
  let osvError    = null;

  if (packages.length > 0) {
    const queries = packages.map(p => ({
      package: { name: p.name, ecosystem: p.ecosystem },
      version: p.version,
    }));

    try {
      const osvResults = await osvBatch(queries);
      for (let idx = 0; idx < packages.length; idx++) {
        const pkg    = packages[idx];
        const result = osvResults[idx];
        if (!result?.vulns?.length) continue;
        for (const vuln of result.vulns) {
          const osvId   = vuln.id ?? 'UNKNOWN';
          const aliases = (vuln.aliases ?? []).filter(a => a.startsWith('CVE-'));
          const fixedIn = getFixedIn(vuln);
          const refs    = (vuln.references ?? []).slice(0, 3).map(r => r.url).filter(Boolean);
          osvFindings.push({
            id:        `SCAN-${osvId}`,
            osv_id:    osvId,
            aliases,
            package:   pkg.name,
            version:   pkg.version,
            ecosystem: pkg.ecosystem,
            summary:   vuln.summary ?? vuln.details?.slice(0, 200) ?? '',
            severity:  getSeverity(vuln),
            fixed_in:  fixedIn ?? 'no fix available',
            references: refs,
          });
        }
      }
    } catch (err) {
      osvError = err.message;
    }
  }

  // ── 10. Blast radius enrichment (async, best-effort) ─────────────────────
  //
  // For the top 8 vulnerable packages (prioritised by severity), fetch monthly
  // download counts so the report can surface "12.3M downloads/month" context.
  // We cap at 8 requests and use a 3s AbortSignal to never block the scan.
  const SEVERITY_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  const enrichCandidates = osvFindings
    .filter(f => f.ecosystem === 'npm' || f.ecosystem === 'PyPI')
    .sort((a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0))
    .slice(0, 8);

  const blastMap = new Map();   // pkg name → blast_radius object
  if (enrichCandidates.length > 0) {
    await Promise.all(
      enrichCandidates.map(async f => {
        if (blastMap.has(f.package)) return;
        const br = await fetchBlastRadius(f.package, f.ecosystem);
        if (br) blastMap.set(f.package, br);
      }),
    );
  }

  // Attach blast_radius to matching OSV findings
  for (const f of osvFindings) {
    if (blastMap.has(f.package)) f.blast_radius = blastMap.get(f.package);
  }

  // ── 11. Merge all findings ────────────────────────────────────────────────
  const allFindings = [
    ...osvFindings,
    ...hookFindings,
    ...secretFindings,
    ...confusionFindings,
    ...ghostFindings,
  ];

  const raw = JSON.stringify({
    packages_scanned:        packages.length,
    vulnerabilities:         osvFindings,
    hooks:                   hookFindings,
    secrets:                 secretFindings,
    dependency_confusion:    confusionFindings,
    ghost_endpoints:         ghostFindings,
    sbom,
    ...(osvError ? { osv_error: osvError } : {}),
  }, null, 2);

  return {
    phase:    'scan',
    status:   allFindings.length > 0 ? 'complete' : 'clean',
    findings: allFindings,
    context:  { ...context, scan: raw },
    raw,
    meta: {
      packages_scanned:       packages.length,
      vulnerabilities_found:  osvFindings.length,
      secrets_found:          secretFindings.length,
      hooks_found:            hookFindings.length,
      ghost_endpoints_found:  ghostFindings.length,
      confusion_suspects:     confusionFindings.length,
      ecosystems:             [...ecosystems],
      target:                 dir,
      sbom_components:        packages.length,
      ...(osvError ? { osv_error: osvError } : {}),
    },
    sbom,
  };
}
