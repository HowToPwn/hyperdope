import { readFileSync, existsSync } from 'fs';
import { join, resolve } from 'path';

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_BATCH_SIZE = 500; // stay under API limits

function stripSemverRange(v) {
  return (v ?? '').replace(/^[\^~>=<]+/, '').trim();
}

// ── Lockfile parsers ─────────────────────────────────────────────────────────

function parsePackageLock(dir) {
  const lockPath = join(dir, 'package-lock.json');
  if (!existsSync(lockPath)) return [];
  const data = JSON.parse(readFileSync(lockPath, 'utf8'));
  const pkgs = [];

  // npm v7+ uses .packages
  if (data.packages) {
    for (const [key, entry] of Object.entries(data.packages)) {
      if (!key || key === '') continue; // skip root
      const name = key.replace(/^node_modules\//, '');
      if (name && entry.version) {
        pkgs.push({ name, version: entry.version, ecosystem: 'npm' });
      }
    }
    return pkgs;
  }

  // npm v6 uses .dependencies
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
    if (match) {
      pkgs.push({ name: match[1], version: match[2], ecosystem: 'PyPI' });
    }
  }
  return pkgs;
}

function parseGoMod(dir) {
  const modPath = join(dir, 'go.mod');
  if (!existsSync(modPath)) return [];
  const content = readFileSync(modPath, 'utf8');
  const pkgs = [];

  // Single-line: require module vX.Y.Z
  const single = content.matchAll(/^require\s+(\S+)\s+(v\S+)/gm);
  for (const m of single) {
    pkgs.push({ name: m[1], version: m[2].replace(/^v/, ''), ecosystem: 'Go' });
  }

  // Block: require ( ... )
  const blockMatch = content.match(/require\s*\(([^)]+)\)/s);
  if (blockMatch) {
    const lines = blockMatch[1].split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('//')) continue;
      const parts = trimmed.split(/\s+/);
      if (parts.length >= 2) {
        pkgs.push({
          name: parts[0],
          version: parts[1].replace(/^v/, ''),
          ecosystem: 'Go',
        });
      }
    }
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
  if (vuln.severity && vuln.severity.length > 0) {
    return vuln.severity[0].score ?? vuln.severity[0].type ?? 'UNKNOWN';
  }
  if (vuln.database_specific?.severity) return vuln.database_specific.severity;
  return 'UNKNOWN';
}

async function osvBatch(queries) {
  if (queries.length === 0) return [];

  const results = [];
  for (let i = 0; i < queries.length; i += OSV_BATCH_SIZE) {
    const batch = queries.slice(i, i + OSV_BATCH_SIZE);
    const resp = await fetch(OSV_BATCH_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queries: batch }),
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

// ── Main ─────────────────────────────────────────────────────────────────────

export async function runScan({ target, context = {} }) {
  const dir = resolve(target);

  // Collect packages from all supported lockfiles
  let packages = [];
  const ecosystems = new Set();

  // npm: prefer lockfile for pinned versions, fall back to package.json
  const npmLock = parsePackageLock(dir);
  if (npmLock.length > 0) {
    packages.push(...npmLock);
    ecosystems.add('npm');
  } else {
    const npmPkg = parsePackageJson(dir);
    if (npmPkg.length > 0) {
      packages.push(...npmPkg);
      ecosystems.add('npm');
    }
  }

  const pyPkgs = parseRequirementsTxt(dir);
  if (pyPkgs.length > 0) { packages.push(...pyPkgs); ecosystems.add('PyPI'); }

  const goPkgs = parseGoMod(dir);
  if (goPkgs.length > 0) { packages.push(...goPkgs); ecosystems.add('Go'); }

  if (packages.length === 0) {
    return {
      phase: 'scan',
      status: 'partial',
      findings: [],
      context: { ...context, scan: JSON.stringify({ error: 'No supported lockfiles found', target: dir }) },
      raw: `No lockfiles found in ${dir}. Supported: package-lock.json, package.json, requirements.txt, go.mod`,
      meta: { packages_scanned: 0, vulnerabilities_found: 0, ecosystems: [], target: dir },
    };
  }

  // Deduplicate by name+version+ecosystem
  const seen = new Set();
  packages = packages.filter(p => {
    const key = `${p.ecosystem}:${p.name}@${p.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Build OSV queries
  const queries = packages.map(p => ({
    package: { name: p.name, ecosystem: p.ecosystem },
    version: p.version,
  }));

  let osvResults;
  try {
    osvResults = await osvBatch(queries);
  } catch (err) {
    return {
      phase: 'scan',
      status: 'partial',
      findings: [],
      context: { ...context, scan: JSON.stringify({ error: err.message }) },
      raw: `OSV API error: ${err.message}`,
      meta: { packages_scanned: packages.length, vulnerabilities_found: 0, ecosystems: [...ecosystems], target: dir },
    };
  }

  // Map results back to findings
  const findings = [];
  for (let idx = 0; idx < packages.length; idx++) {
    const pkg = packages[idx];
    const result = osvResults[idx];
    if (!result?.vulns?.length) continue;

    for (const vuln of result.vulns) {
      const osvId = vuln.id ?? 'UNKNOWN';
      const aliases = (vuln.aliases ?? []).filter(a => a.startsWith('CVE-'));
      const fixedIn = getFixedIn(vuln);
      const refs = (vuln.references ?? [])
        .slice(0, 3)
        .map(r => r.url)
        .filter(Boolean);

      findings.push({
        id: `SCAN-${osvId}`,
        osv_id: osvId,
        aliases,
        package: pkg.name,
        version: pkg.version,
        ecosystem: pkg.ecosystem,
        summary: vuln.summary ?? vuln.details?.slice(0, 200) ?? '',
        severity: getSeverity(vuln),
        fixed_in: fixedIn ?? 'no fix available',
        references: refs,
      });
    }
  }

  const raw = JSON.stringify({ packages_scanned: packages.length, findings }, null, 2);

  return {
    phase: 'scan',
    status: findings.length > 0 ? 'complete' : 'clean',
    findings,
    context: { ...context, scan: raw },
    raw,
    meta: {
      packages_scanned: packages.length,
      vulnerabilities_found: findings.length,
      ecosystems: [...ecosystems],
      target: dir,
    },
  };
}
