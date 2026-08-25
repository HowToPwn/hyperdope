import { readFileSync, existsSync, readdirSync, statSync } from 'fs';
import { join, resolve, extname } from 'path';

const OSV_BATCH_URL  = 'https://api.osv.dev/v1/querybatch';
const OSV_BATCH_SIZE = 500;

// ── Lockfile parsers ─────────────────────────────────────────────────────────

function stripSemverRange(v) {
  return (v ?? '').replace(/^[\^~>=<]+/, '').trim();
}

function parsePackageLock(dir) {
  const lockPath = join(dir, 'package-lock.json');
  if (!existsSync(lockPath)) return [];
  const data = JSON.parse(readFileSync(lockPath, 'utf8'));
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
  const data = JSON.parse(readFileSync(pkgPath, 'utf8'));
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
    const data = JSON.parse(readFileSync(lockPath, 'utf8'));
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
  for (const name of SCAN_FILES) {
    const fp = join(dir, name);
    if (existsSync(fp)) {
      try { scanContent(fp, readFileSync(fp, 'utf8')); } catch { /* skip unreadable */ }
    }
  }

  // Scan one level deep for files with sensitive extensions (avoid recursion into node_modules)
  try {
    for (const entry of readdirSync(dir)) {
      if (SKIP_DIRS.has(entry)) continue;
      const fp   = join(dir, entry);
      const stat = statSync(fp);
      if (!stat.isFile()) continue;
      if (SCAN_EXTENSIONS.has(extname(entry).toLowerCase())) {
        try { scanContent(fp, readFileSync(fp, 'utf8')); } catch { /* skip */ }
      }
    }
  } catch { /* unreadable dir */ }

  return secrets;
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

  // ── 2. Postinstall hook detection (npm) ──────────────────────────────────
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

  // ── 4. No packages + no secrets + no hooks ───────────────────────────────
  if (packages.length === 0 && hookFindings.length === 0 && secretFindings.length === 0) {
    return {
      phase:    'scan',
      status:   'partial',
      findings: [],
      context:  { ...context, scan: JSON.stringify({ error: 'No supported lockfiles found', target: dir }) },
      raw:      `No lockfiles found in ${dir}. Supported: package-lock.json, package.json, requirements.txt, poetry.lock, Pipfile.lock, go.mod, Cargo.lock`,
      meta:     { packages_scanned: 0, vulnerabilities_found: 0, secrets_found: 0, hooks_found: 0, ecosystems: [], target: dir },
    };
  }

  // ── 5. Deduplicate packages ───────────────────────────────────────────────
  const seen = new Set();
  packages = packages.filter(p => {
    const key = `${p.ecosystem}:${p.name}@${p.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // ── 6. SBOM generation ────────────────────────────────────────────────────
  const sbom = buildSbom(packages, dir);

  // ── 7. OSV vulnerability scan ─────────────────────────────────────────────
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

  // ── 8. Merge all findings ─────────────────────────────────────────────────
  const allFindings = [...osvFindings, ...hookFindings, ...secretFindings];
  const raw         = JSON.stringify({
    packages_scanned:   packages.length,
    vulnerabilities:    osvFindings,
    hooks:              hookFindings,
    secrets:            secretFindings,
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
      packages_scanned:      packages.length,
      vulnerabilities_found: osvFindings.length,
      secrets_found:         secretFindings.length,
      hooks_found:           hookFindings.length,
      ecosystems:            [...ecosystems],
      target:                dir,
      sbom_components:       packages.length,
      ...(osvError ? { osv_error: osvError } : {}),
    },
    sbom,
  };
}
