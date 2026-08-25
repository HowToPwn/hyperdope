#!/usr/bin/env node
/**
 * hd-run — Hyperdope standalone pipeline runner
 *
 * Run the full 6-phase audit pipeline (or a single phase) directly from the
 * terminal — no MCP client required.
 *
 * Usage:
 *   npx hd-run --agent agent.yaml --target https://github.com/org/repo
 *
 * Options:
 *   --agent   <path>    Path to agent.yaml (required for LLM phases)
 *   --target  <value>   Target: repo URL, directory path, or descriptor
 *   --phase   <name>    Run only one phase: scan|profile|audit|confirm|assess|draft_ghsa|disclose|verify
 *   --resume-from <n>   Resume pipeline from this phase (requires --session-file)
 *   --session-file <p>  Prior session JSON to load completed phase contexts from
 *   --json              Write full JSON result to stdout (stderr gets the TUI)
 *   --out <path>        Write JSON result to a file instead of stdout
 *
 * Exit codes:
 *   0  — Pipeline completed successfully
 *   1  — One or more phases failed
 *   2  — Invalid arguments or config error
 */

import { writeFileSync, readFileSync, existsSync, realpathSync } from 'fs';
import { resolve, relative, isAbsolute } from 'path';

import { loadAgentConfig }    from '../src/config.js';
import { callProvider }       from '../src/providers/index.js';
import { initSession, writePhaseToSession, sessionPath, newSessionTimestamp } from '../src/session.js';
import { trimContext }        from '../src/context.js';
import {
  runProfile, runAudit, runConfirm, runAssess,
  runDraftGhsa, runDisclose, runScan, runVerify,
} from '../src/phases/index.js';
import {
  Spinner, println, gap, printDivider,
  printHeader, printKv,
  printPassBanner, printFailBanner, phaseSummary,
  bold, dim, red, cyan,
  phaseLabel, severityBadge, severityColor,
} from '../src/tui.js';

// ── Phase registry ────────────────────────────────────────────────────────────

const PHASE_FNS = {
  scan:       { fn: runScan,      noLlm: true },
  profile:    { fn: runProfile },
  audit:      { fn: runAudit },
  confirm:    { fn: runConfirm },
  assess:     { fn: runAssess },
  draft_ghsa: { fn: runDraftGhsa },
  disclose:   { fn: runDisclose },
  verify:     { fn: runVerify },
};

const FULL_PIPELINE = ['profile', 'audit', 'confirm', 'assess', 'draft_ghsa', 'disclose'];

// ── Argument parsing ──────────────────────────────────────────────────────────

function parseArgs(argv) {
  const args = {
    agent:       null,
    target:      null,
    phase:       null,
    resumeFrom:  null,
    sessionFile: null,
    json:        false,
    out:         null,
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if ((a === '--agent'        || a === '-a') && argv[i + 1]) args.agent       = argv[++i];
    if ((a === '--target'       || a === '-t') && argv[i + 1]) args.target      = argv[++i];
    if ((a === '--phase'        || a === '-p') && argv[i + 1]) args.phase       = argv[++i];
    if ((a === '--resume-from'  || a === '-r') && argv[i + 1]) args.resumeFrom  = argv[++i];
    if ((a === '--session-file' || a === '-s') && argv[i + 1]) args.sessionFile = argv[++i];
    if ((a === '--out'          || a === '-o') && argv[i + 1]) args.out         = argv[++i];
    if (a === '--json' || a === '-j') args.json = true;
    if (a === '--help' || a === '-h') { printHelp(); process.exit(0); }
  }

  return args;
}

function printHelp() {
  println('');
  println(bold('  hd-run') + dim(' — Hyperdope pipeline runner'));
  println('');
  println(bold('  Usage'));
  println(dim('  ─────────────────────────────────────────────'));
  println('  npx hd-run --agent agent.yaml --target <target>');
  println('');
  println(bold('  Options'));
  println(dim('  ─────────────────────────────────────────────'));
  printKv([
    ['--agent   <path>',       'Path to agent.yaml config'],
    ['--target  <value>',      'Repo URL, directory, or descriptor'],
    ['--phase   <name>',       'Run single phase only (scan|profile|audit|confirm|assess|draft_ghsa|disclose|verify)'],
    ['--resume-from <phase>',  'Resume pipeline from this phase'],
    ['--session-file <path>',  'Session JSON from a prior hd-run (required with --resume-from)'],
    ['--json',                 'Write result JSON to stdout'],
    ['--out <path>',           'Write result JSON to file'],
    ['--help',                 'Show this help'],
  ]);
  println('');
  println(bold('  Examples'));
  println(dim('  ─────────────────────────────────────────────'));
  println('  npx hd-run --agent agent.yaml --target https://github.com/org/repo');
  println('  npx hd-run --agent agent.yaml --target ./ --phase scan');
  println('  npx hd-run --agent agent.yaml --target ./ --resume-from confirm \\');
  println('             --session-file .hyperdope-session-20260825.json');
  println('');
}

function die(msg) {
  println(red('  ✗  ' + msg));
  println(dim('  Run --help for usage.'));
  gap();
  process.exit(2);
}

// ── Phase execution ───────────────────────────────────────────────────────────

async function runPhase(name, { config, target, ctx }) {
  const { fn, noLlm } = PHASE_FNS[name];
  const phaseConfig = config?.phases?.[name] ?? null;
  const trimmed     = noLlm ? (ctx ?? {}) : trimContext(ctx ?? {}, name);

  if (noLlm) {
    return await fn({ target, context: trimmed });
  }
  return await fn({ config, target, context: trimmed, callProvider, phaseConfig });
}

// ── Phase result display ──────────────────────────────────────────────────────

function displayPhaseResult(name, result) {
  const findings = result?.findings ?? [];
  if (findings.length === 0) return;

  // For scan: show grouped findings; for others: show top findings
  if (name === 'scan') {
    const groups = {};
    for (const f of findings) {
      const sev = f.severity?.toLowerCase() ?? 'info';
      (groups[sev] ??= []).push(f);
    }
    for (const sev of ['critical', 'high', 'medium', 'low']) {
      const group = groups[sev];
      if (!group?.length) continue;
      println(`    ${severityBadge(sev)} ${dim(group.length + ' finding' + (group.length === 1 ? '' : 's'))}`);
      for (const f of group.slice(0, 3)) {
        println(`      ${dim('·')} ${(f.title ?? f.summary ?? '').slice(0, 68)}`);
        if (f.component) println(`          ${dim(f.component)}`);
      }
      if (group.length > 3) println(`      ${dim(`… and ${group.length - 3} more`)}`);
    }
  } else {
    const preview = findings.slice(0, 4);
    for (const f of preview) {
      const title = (f.title ?? f.id ?? '').slice(0, 68);
      const sev   = f.severity_estimate ?? f.severity;
      println(`    ${dim('·')} ${sev ? `[${severityColor(sev, sev.toUpperCase())}] ` : ''}${title}`);
    }
    if (findings.length > 4) println(`    ${dim(`… and ${findings.length - 4} more`)}`);
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (!args.target) die('--target is required');

  // ── Load config (optional for scan-only) ───────────────────────────────────

  let config = null;
  if (args.agent) {
    try {
      config = loadAgentConfig(args.agent);
    } catch (err) {
      die(`Failed to load agent config: ${err.message}`);
    }
  }

  const targetLabel = args.target.length > 52
    ? '…' + args.target.slice(-51)
    : args.target;

  // ── Single phase mode ──────────────────────────────────────────────────────

  if (args.phase) {
    if (!PHASE_FNS[args.phase]) {
      die(`Unknown phase "${args.phase}". Valid: ${Object.keys(PHASE_FNS).join(' | ')}`);
    }
    if (!PHASE_FNS[args.phase].noLlm && !config) {
      die(`--agent is required for phase "${args.phase}"`);
    }

    printHeader(`hd-run  ·  ${args.phase}`, targetLabel);
    printKv([
      ['Phase',  bold(args.phase)],
      ['Target', dim(args.target)],
      ...(args.agent ? [['Agent', dim(args.agent)]] : []),
    ]);

    const spinner = new Spinner(`Running ${bold(args.phase)}…`).start();
    let result;
    try {
      result = await runPhase(args.phase, { config, target: args.target, ctx: {} });
    } catch (err) {
      spinner.fail(`${args.phase} failed: ${err.message}`);
      if (err.stack) println(dim('\n' + err.stack));
      process.exit(1);
    }

    const summary = phaseSummary(args.phase, result);
    spinner.succeed(`${bold(args.phase)} — ${summary}`);
    gap();
    displayPhaseResult(args.phase, result);

    // Persist
    const sf = sessionPath(newSessionTimestamp());
    writePhaseToSession(sf, args.phase, result);
    gap();
    println(`  ${cyan('ℹ')}  ${dim('Session saved →')} ${dim(sf)}`);

    if (args.out) {
      writeFileSync(resolve(args.out), JSON.stringify(result, null, 2), 'utf8');
      println(`  ${cyan('ℹ')}  ${dim('Result written →')} ${dim(resolve(args.out))}`);
    }
    if (args.json) {
      process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    }

    process.exit(result.status === 'complete' || result.status === 'clean' ? 0 : 0);
  }

  // ── Full pipeline mode ─────────────────────────────────────────────────────

  if (!config) die('--agent is required for the full pipeline');

  printHeader('hd-run  ·  Full Pipeline', targetLabel);
  printKv([
    ['Target',      dim(args.target)],
    ['Agent',       dim(args.agent)],
    ['Resume from', args.resumeFrom ? bold(args.resumeFrom) : dim('—')],
    ['Session file',args.sessionFile ? dim(args.sessionFile) : dim('—')],
  ]);
  gap();

  // ── Load resume context ────────────────────────────────────────────────────

  let initialCtx = {};
  let skipBefore = null;

  if (args.resumeFrom) {
    if (!args.sessionFile) die('--resume-from requires --session-file');
    const cwd = process.cwd();
    const absSession = resolve(args.sessionFile);
    const relSession = relative(cwd, absSession);
    if (relSession.startsWith('..') || isAbsolute(relSession)) {
      die(`session-file traverses outside working directory: ${args.sessionFile}`);
    }
    if (!existsSync(absSession)) die(`session-file not found: ${args.sessionFile}`);
    try {
      const realCwd = realpathSync(cwd);
      const realSession = realpathSync(absSession);
      const relReal = relative(realCwd, realSession);
      if (relReal.startsWith('..') || isAbsolute(relReal)) {
        die(`session-file resolves outside working directory: ${args.sessionFile}`);
      }
    } catch {
      die(`session-file cannot be accessed: ${args.sessionFile}`);
    }
    if (!FULL_PIPELINE.includes(args.resumeFrom)) {
      die(`Invalid resume phase "${args.resumeFrom}". Valid: ${FULL_PIPELINE.join(' | ')}`);
    }

    try {
      const sessionData = JSON.parse(readFileSync(absSession, 'utf8'));
      for (const name of FULL_PIPELINE) {
        if (name === args.resumeFrom) break;
        const pr = sessionData.phases?.[name];
        if (pr?.context) initialCtx = { ...initialCtx, ...pr.context };
      }
      skipBefore = args.resumeFrom;
    } catch (err) {
      die(`Failed to read session file: ${err.message}`);
    }
  }

  // ── Session init ───────────────────────────────────────────────────────────

  const sessionFile = initSession(args.target, args.agent);
  const results     = {};
  const skipped     = [];
  let ctx           = initialCtx;
  let pipelineOk    = true;
  let resumeActive  = skipBefore === null;

  // ── Phase progress header ──────────────────────────────────────────────────

  const TOTAL = FULL_PIPELINE.length;

  // ── Run phases ─────────────────────────────────────────────────────────────

  for (let pi = 0; pi < FULL_PIPELINE.length; pi++) {
    const name    = FULL_PIPELINE[pi];
    const stepNum = `${String(pi + 1)}/${TOTAL}`;

    if (!resumeActive) {
      if (name === skipBefore) {
        resumeActive = true;
      } else {
        skipped.push(name);
        println(`  ${dim('○')}  ${phaseLabel(name)} ${dim(`[skipped]`)}`);
        continue;
      }
    }

    const spinner = new Spinner(
      `${dim(stepNum)}  ${phaseLabel(name)}`
    ).start();

    let result;
    try {
      result = await runPhase(name, { config, target: args.target, ctx });
    } catch (err) {
      spinner.fail(`${phaseLabel(name)} ${red('failed')}  ${dim(err.message)}`);
      if (err.stack) println(dim('\n' + err.stack.split('\n').slice(1, 4).join('\n')));
      pipelineOk = false;
      break;
    }

    const summary = phaseSummary(name, result);
    spinner.succeed(`${dim(stepNum)}  ${phaseLabel(name)} ${dim('→')} ${summary}`);

    // Show brief preview of interesting findings
    if (result?.findings?.length > 0) {
      displayPhaseResult(name, result);
    }

    writePhaseToSession(sessionFile, name, result);
    results[name] = result;
    ctx = result.context;
  }

  // ── Final summary ──────────────────────────────────────────────────────────

  gap();
  printDivider();
  gap();
  printKv([
    ['Session',   dim(sessionFile)],
    ['Completed', bold(String(Object.keys(results).length)) + dim(' phases')],
    ...(skipped.length ? [['Skipped', dim(skipped.join(', '))]] : []),
  ]);
  gap();

  if (pipelineOk) {
    printPassBanner(`${Object.keys(results).length}/${TOTAL} phases complete`);
  } else {
    printFailBanner('Pipeline interrupted');
  }

  // ── Output ─────────────────────────────────────────────────────────────────

  const output = {
    session_file:     sessionFile,
    target:           args.target,
    phases_completed: Object.keys(results),
    phases_skipped:   skipped,
    resumed_from:     args.resumeFrom ?? null,
    results,
  };

  if (args.out) {
    writeFileSync(resolve(args.out), JSON.stringify(output, null, 2), 'utf8');
    println(`  ${cyan('ℹ')}  ${dim('JSON written →')} ${dim(resolve(args.out))}`);
  }
  if (args.json) {
    process.stdout.write(JSON.stringify(output, null, 2) + '\n');
  }

  process.exit(pipelineOk ? 0 : 1);
}

main().catch(err => {
  process.stderr.write(red(`\n  ✗  Unhandled error: ${err.message}\n`));
  if (err.stack) process.stderr.write(dim(err.stack) + '\n');
  process.exit(2);
});
