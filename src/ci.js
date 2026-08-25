/**
 * Hyperdope CI mode (hd-ci)
 * --------------------------
 * Scan a directory for CVEs, secrets, and supply-chain hooks.
 * Exports SARIF 2.1.0 for GitHub Code Scanning.
 * Exits 1 if findings meet/exceed the severity threshold.
 *
 * Usage:
 *   npx hd-ci --target ./ [--threshold high] [--sarif-out ./results.sarif.json] [--json]
 */

import { writeFileSync } from 'fs';
import { resolve } from 'path';
import { runScan } from './phases/scan.js';
import { normalizeFindings, exportSarif } from './schema.js';
import {
  Spinner, println, gap, printDivider, printHeader,
  printKv, printFinding, printPassBanner, printFailBanner,
  phaseSummary, bold, dim, red, green, yellow, cyan,
  bRed, bGreen, bYellow, severityBadge, severityColor, USE_COLOR,
} from './tui.js';

// ── Severity ordering ─────────────────────────────────────────────────────────

const SEVERITY_ORDER = ['none', 'info', 'low', 'medium', 'high', 'critical'];

function exceedsThreshold(found, threshold) {
  return SEVERITY_ORDER.indexOf(found) >= SEVERITY_ORDER.indexOf(threshold);
}

// ── Argument parsing ──────────────────────────────────────────────────────────

function parseArgs(argv) {
  const args = {
    target:    '.',
    threshold: 'high',
    sarifOut:  null,
    json:      false,
    noColor:   false,
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if ((a === '--target'    || a === '-t') && argv[i + 1]) { args.target    = argv[++i]; }
    if ((a === '--threshold' || a === '-T') && argv[i + 1]) { args.threshold = argv[++i].toLowerCase(); }
    if ((a === '--sarif-out' || a === '-o') && argv[i + 1]) { args.sarifOut  = argv[++i]; }
    if (a === '--json'     || a === '-j') args.json     = true;
    if (a === '--no-color' || a === '--no-colours') args.noColor = true;
  }

  if (!SEVERITY_ORDER.includes(args.threshold)) {
    process.stderr.write(
      `[hd-ci] Unknown threshold "${args.threshold}". ` +
      `Valid: ${SEVERITY_ORDER.join(' | ')}\n`
    );
    process.exit(2);
  }

  return args;
}

// ── Formatted finding list ────────────────────────────────────────────────────

function printFindings(findings, label, emptyMsg) {
  if (findings.length === 0) {
    println(`  ${dim('○')}  ${dim(emptyMsg)}`);
    return;
  }
  println(`  ${bold(label)}  ${dim(`(${findings.length})`)}`);
  gap();
  for (let i = 0; i < findings.length; i++) {
    printFinding(findings[i], i);
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

export async function runCi(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const targetAbs = resolve(args.target);

  if (!args.json) {
    printHeader('Hyperdope  hd-ci', 'Dependency · Secrets · Supply-chain scanner');
    printKv([
      ['Target',    dim(targetAbs)],
      ['Threshold', severityColor(args.threshold, args.threshold.toUpperCase())],
      ['SARIF out', args.sarifOut ? dim(resolve(args.sarifOut)) : dim('—')],
    ]);
    gap();
  }

  // ── Scan ────────────────────────────────────────────────────────────────────

  const spinner = new Spinner('Scanning dependencies…').start();
  let scanResult;

  try {
    scanResult = await runScan({ target: targetAbs });
  } catch (err) {
    spinner.fail(`Scan failed: ${err.message}`);
    if (!args.json) process.stderr.write(`\n  ${red(err.stack ?? err.message)}\n`);
    process.exit(2);
  }

  const summaryText = phaseSummary('scan', scanResult);
  if (scanResult.meta?.osv_error) {
    spinner.warn(`Scan complete (OSV partial): ${summaryText}`);
  } else {
    spinner.succeed(`Scan complete: ${summaryText}`);
  }

  // ── Normalize & SARIF ───────────────────────────────────────────────────────

  const normalized = normalizeFindings(scanResult.findings, 'scan');
  const breaching  = normalized.filter(f => exceedsThreshold(f.severity, args.threshold));

  const sarif = exportSarif(normalized, { tool: 'hyperdope', version: '0.3.0' });

  if (args.sarifOut) {
    const outPath = resolve(args.sarifOut);
    writeFileSync(outPath, JSON.stringify(sarif, null, 2), 'utf8');
    if (!args.json) println(`  ${cyan('ℹ')}  SARIF written → ${dim(outPath)}`);
  }

  // ── Human-readable output ───────────────────────────────────────────────────

  if (!args.json) {
    const meta = scanResult.meta ?? {};
    gap();
    printDivider();

    // Stats row
    const stats = [
      ['Packages',        String(meta.packages_scanned  ?? 0)],
      ['Ecosystems',      (meta.ecosystems ?? []).join(', ') || dim('none')],
      ['CVEs found',      meta.vulnerabilities_found
                            ? severityColor('high', String(meta.vulnerabilities_found))
                            : green('0')],
      ['Secrets found',   meta.secrets_found
                            ? severityColor('critical', String(meta.secrets_found))
                            : green('0')],
      ['Hooks flagged',   meta.hooks_found
                            ? severityColor('medium', String(meta.hooks_found))
                            : green('0')],
      ['Total findings',  bold(String(normalized.length))],
      ['Breaching',       breaching.length
                            ? bold(severityColor(args.threshold, String(breaching.length)))
                            : green('0')],
    ];
    gap();
    printKv(stats);
    printDivider();

    if (normalized.length > 0) {
      // Group by severity for display
      for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
        const group = normalized.filter(f => f.severity === sev);
        if (group.length === 0) continue;
        gap();
        println(`  ${severityBadge(sev)} ${bold(String(group.length) + ' finding' + (group.length === 1 ? '' : 's'))}`);
        for (let i = 0; i < group.length; i++) {
          const f = group[i];
          const title = (f.title ?? '').slice(0, 62);
          println(`    ${dim('·')} ${title}`);
          if (f.component) println(`        ${dim(f.component)}`);
        }
      }
      gap();
      printDivider();
    }

    if (meta.osv_error) {
      gap();
      println(`  ${yellow('⚠')}  OSV API warning: ${dim(meta.osv_error)}`);
    }

    // Pass / Fail banner
    const thresholdLabel = args.threshold.toUpperCase();
    if (breaching.length > 0) {
      printFailBanner(`${breaching.length} finding(s) ≥ ${thresholdLabel}`);
    } else {
      printPassBanner(`No findings ≥ ${thresholdLabel}`);
    }
  }

  // ── JSON output ─────────────────────────────────────────────────────────────

  const summary = {
    target:             targetAbs,
    threshold:          args.threshold,
    packages_scanned:   scanResult.meta?.packages_scanned  ?? 0,
    vulnerabilities:    scanResult.meta?.vulnerabilities_found ?? 0,
    secrets_found:      scanResult.meta?.secrets_found     ?? 0,
    hooks_found:        scanResult.meta?.hooks_found        ?? 0,
    total_findings:     normalized.length,
    breaching_findings: breaching.length,
    ecosystems:         scanResult.meta?.ecosystems ?? [],
    findings:           normalized.map(f => ({
      id:        f.id,
      severity:  f.severity,
      title:     f.title,
      component: f.component,
      evidence:  f.evidence,
    })),
    breaching: breaching.map(f => ({
      id:        f.id,
      severity:  f.severity,
      title:     f.title,
      component: f.component,
      evidence:  f.evidence,
    })),
    sarif_path: args.sarifOut ? resolve(args.sarifOut) : null,
  };

  if (args.json) {
    process.stdout.write(JSON.stringify(
      args.sarifOut ? { ...summary, sarif } : summary,
      null, 2
    ) + '\n');
  }

  // ── Exit code ────────────────────────────────────────────────────────────────

  if (breaching.length > 0) {
    process.exit(1);
  }
  process.exit(0);
}
