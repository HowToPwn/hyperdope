import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { existsSync, readFileSync, realpathSync } from 'fs';
import { resolve, relative, isAbsolute } from 'path';
import { loadAgentConfig } from './config.js';
import { callProvider } from './providers/index.js';
import {
  runProfile,
  runAudit,
  runConfirm,
  runAssess,
  runDraftGhsa,
  runDisclose,
  runScan,
  runVerify,
} from './phases/index.js';
import { initSession, writePhaseToSession, newSessionTimestamp, sessionPath } from './session.js';
import { trimContext } from './context.js';

// ── Shared input schemas ──────────────────────────────────────────────────────

const toolInput = z.object({
  agent:   z.string().describe('Path to agent.yaml config file'),
  target:  z.string().describe('Target descriptor: repo URL, domain, binary path, etc.'),
  context: z.record(z.unknown()).optional().describe('Prior phase output to resume from'),
});

const scanInput = z.object({
  target:  z.string().describe('Directory path containing lockfiles (package-lock.json, requirements.txt, go.mod, Cargo.lock, poetry.lock, Pipfile.lock)'),
  context: z.record(z.unknown()).optional().describe('Prior phase output to merge into scan context'),
});

const verifyInput = z.object({
  agent:         z.string().describe('Path to agent.yaml config file'),
  target:        z.string().describe('Descriptor of the patched version: git commit SHA, version tag, diff URL, or patched file listing'),
  context:       z.record(z.unknown()).optional().describe('Prior pipeline context containing audit, confirm, and assess outputs'),
});

// Phases that can be used as resume points in hd_run
const PHASE_NAMES = ['profile', 'audit', 'confirm', 'assess', 'draft_ghsa', 'disclose'];

const runInput = z.object({
  agent:       z.string().describe('Path to agent.yaml config file'),
  target:      z.string().describe('Target descriptor: repo URL, domain, binary path, etc.'),
  context:     z.record(z.unknown()).optional().describe('Initial context to seed into the pipeline'),
  resume_from: z.enum(PHASE_NAMES).optional()
    .describe('Phase to resume from (skips completed earlier phases). Requires session_file.'),
  session_file: z.string().optional()
    .describe('Path to an existing .hyperdope-session.json file produced by a prior hd_run. Used with resume_from.'),
});

/**
 * Enforce that session_file stays within the current working directory and does
 * not escape via path traversal or symlinks.
 */
function validateSessionPath(sessionFile) {
  const cwd = process.cwd();
  const absPath = resolve(sessionFile);
  const rel = relative(cwd, absPath);
  if (rel.startsWith('..') || isAbsolute(rel)) {
    throw new Error(`session_file traverses outside working directory: "${sessionFile}"`);
  }
  if (!existsSync(absPath)) {
    throw new Error(`session_file not found: ${sessionFile}`);
  }
  try {
    const realCwd = realpathSync(cwd);
    const realSession = realpathSync(absPath);
    const relReal = relative(realCwd, realSession);
    if (relReal.startsWith('..') || isAbsolute(relReal)) {
      throw new Error(`session_file resolves outside working directory: "${sessionFile}"`);
    }
  } catch (err) {
    if (err.message.includes('outside working directory')) throw err;
    throw new Error(`session_file cannot be accessed: ${sessionFile}`);
  }
  return absPath;
}

// ── Phase handler factory ─────────────────────────────────────────────────────

function makePhaseHandler(phaseName, runFn) {
  return async ({ agent, target, context }) => {
    let config;
    try {
      config = loadAgentConfig(agent);
    } catch (err) {
      return {
        content: [{ type: 'text', text: JSON.stringify({
          phase:  phaseName,
          status: 'error',
          error:  err.message,
          hint:   'Check that agent.yaml exists and contains valid provider/model/api_key fields.',
        }, null, 2) }],
        isError: true,
      };
    }

    const phaseConfig = config.phases?.[phaseName] ?? null;
    const trimmed = trimContext(context ?? {}, phaseName);

    let result;
    try {
      result = await runFn({ config, target, context: trimmed, callProvider, phaseConfig });
    } catch (err) {
      return {
        content: [{ type: 'text', text: JSON.stringify({
          phase:  phaseName,
          status: 'error',
          error:  err.message,
          ...(err.stack ? { stack: err.stack.replace(/sk-[A-Za-z0-9-]{20,}/g, 'sk-[REDACTED]') } : {}),
        }, null, 2) }],
        isError: true,
      };
    }

    const sf = sessionPath(newSessionTimestamp());
    writePhaseToSession(sf, phaseName, result);

    return {
      content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
    };
  };
}

// ── Server factory ────────────────────────────────────────────────────────────

export function createServer() {
  const server = new McpServer({
    name:    'hyperdope',
    version: '0.3.1',
    instructions: `Hyperdope is a 6-phase adversarial security research pipeline.

WORKFLOW:
1. hd_scan   — Scan dependencies, secrets, hooks (no API key needed). Run this first on any local target.
2. hd_profile — Map the attack surface (STRIDE, data flows, trust boundaries).
3. hd_audit  — Hunt vulnerabilities (OWASP Top 10, SANS 25, LLM Top 10).
4. hd_confirm — Generate PoCs with reliability ratings.
5. hd_assess — Score with CVSS v3.1 (mathematically verified, not LLM-guessed).
6. hd_draft_ghsa — Draft a GitHub Security Advisory.
7. hd_disclose — Generate executive brief + technical advisory + vendor email.

Use hd_run to execute all 6 LLM phases automatically with context chaining.
Use hd_verify after a patch is available to confirm the fix.

SETUP: An agent.yaml config file specifying provider and API key is required for
all LLM phases (hd_profile through hd_disclose, hd_verify). hd_scan runs without it.

Example agent.yaml:
  provider: claude
  model: claude-sonnet-4-6
  api_key: \${CLAUDE_API_KEY}`,
  });

  // ── Phase 0: Dependency scan ──────────────────────────────────────────────

  server.tool(
    'hd_scan',
    'Phase 0: Scan dependencies against OSV.dev CVE database — no API key required. ' +
    'Supports npm (package-lock.json / package.json), Python (requirements.txt / poetry.lock / Pipfile.lock), ' +
    'Go (go.mod), Rust (Cargo.lock). Also detects hardcoded secrets in config files and ' +
    'suspicious npm lifecycle hooks (postinstall / preinstall / prepare). Returns SBOM-lite.',
    scanInput.shape,
    async ({ target, context }) => {
      try {
        const result = await runScan({ target, context: context ?? {} });
        const sf = sessionPath(newSessionTimestamp());
        writePhaseToSession(sf, 'scan', result);
        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
      } catch (err) {
        return {
          content: [{ type: 'text', text: JSON.stringify({
            phase: 'scan', status: 'error', error: err.message,
          }, null, 2) }],
          isError: true,
        };
      }
    }
  );

  // ── Phase 1: Attack surface profile ──────────────────────────────────────

  server.tool(
    'hd_profile',
    'Phase 1: Map the target attack surface — STRIDE threat model, data flows, trust boundaries, ' +
    'parsers, deserialization, supply chain, auth flows, LLM surfaces',
    toolInput.shape,
    makePhaseHandler('profile', runProfile)
  );

  // ── Phase 2: Adversarial audit ────────────────────────────────────────────

  server.tool(
    'hd_audit',
    'Phase 2: 5-step adversarial vulnerability hunt — entry point inventory, source→sink tracing, ' +
    'control gap analysis, assumption violation, chain candidates. OWASP Top 10, SANS 25, LLM Top 10.',
    toolInput.shape,
    makePhaseHandler('audit', runAudit)
  );

  // ── Phase 3: PoC confirmation ─────────────────────────────────────────────

  server.tool(
    'hd_confirm',
    'Phase 3: Generate up to 3 PoCs ordered by exploitability, with reliability rating and detection likelihood',
    toolInput.shape,
    makePhaseHandler('confirm', runConfirm)
  );

  // ── Phase 4: CVSS assessment ──────────────────────────────────────────────

  server.tool(
    'hd_assess',
    'Phase 4: CVSS v3.1 scoring with per-metric chain-of-thought; score verified mathematically ' +
    'from the vector string — LLM cannot hallucinate the number',
    toolInput.shape,
    makePhaseHandler('assess', runAssess)
  );

  // ── Phase 5: GHSA draft ───────────────────────────────────────────────────

  server.tool(
    'hd_draft_ghsa',
    'Phase 5: GitHub Security Advisory draft (GHSA schema), remediation priority P1/P2/P3, ' +
    'disclosure readiness checklist',
    toolInput.shape,
    makePhaseHandler('draft_ghsa', runDraftGhsa)
  );

  // ── Phase 6: Coordinated disclosure ──────────────────────────────────────

  server.tool(
    'hd_disclose',
    'Phase 6: Coordinated disclosure package — executive brief, full technical advisory with ' +
    'IoCs and remediation, vendor notification email with 90-day timeline table',
    toolInput.shape,
    makePhaseHandler('disclose', runDisclose)
  );

  // ── Phase V: Patch verification ───────────────────────────────────────────

  server.tool(
    'hd_verify',
    'Verification phase: Determine whether reported vulnerabilities are PATCHED, STILL_VULNERABLE, ' +
    'PARTIAL_FIX, or CANNOT_VERIFY in a patched target. ' +
    'Uses 4-question methodology: root cause identification → change analysis → variant bypass check → sibling site audit. ' +
    'Run after hd_assess (or hd_confirm) when a patch is available.',
    verifyInput.shape,
    async ({ agent, target, context }) => {
      let config;
      try {
        config = loadAgentConfig(agent);
      } catch (err) {
        return {
          content: [{ type: 'text', text: JSON.stringify({
            phase: 'verify', status: 'error', error: err.message,
            hint: 'Check that agent.yaml exists and contains valid provider/model/api_key fields.',
          }, null, 2) }],
          isError: true,
        };
      }
      const phaseConfig = config.phases?.verify ?? null;
      const trimmed     = trimContext(context ?? {}, 'verify');
      let result;
      try {
        result = await runVerify({ config, target, context: trimmed, callProvider, phaseConfig });
      } catch (err) {
        return {
          content: [{ type: 'text', text: JSON.stringify({
            phase: 'verify', status: 'error', error: err.message,
            ...(err.stack ? { stack: err.stack.replace(/sk-[A-Za-z0-9-]{20,}/g, 'sk-[REDACTED]') } : {}),
          }, null, 2) }],
          isError: true,
        };
      }

      const sf = sessionPath(newSessionTimestamp());
      writePhaseToSession(sf, 'verify', result);
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  // ── Full pipeline: hd_run (resumable) ────────────────────────────────────

  server.tool(
    'hd_run',
    'Run all 6 LLM phases sequentially (profile → audit → confirm → assess → draft_ghsa → disclose) ' +
    'with automatic context chaining and trimming. ' +
    'Supports resuming from a specific phase via resume_from + session_file — ' +
    'reads completed phase contexts from the session file, skips phases before the resume point, ' +
    'and continues from there with full context re-loaded.',
    runInput.shape,
    async ({ agent, target, context, resume_from, session_file }) => {
      let config;
      try {
        config = loadAgentConfig(agent);
      } catch (err) {
        return {
          content: [{ type: 'text', text: JSON.stringify({
            phase: 'run', status: 'error', error: err.message,
            hint: 'Check that agent.yaml exists and contains valid provider/model/api_key fields.',
          }, null, 2) }],
          isError: true,
        };
      }

      // ── Resume: load completed phases from session file ─────────────────
      let initialCtx = context ?? {};
      let skipBefore = null; // phase name to resume from (all prior phases are skipped)

      if (resume_from) {
        if (!session_file) {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                error: 'resume_from requires session_file. Provide the path to the session JSON produced by a prior hd_run.',
              }, null, 2),
            }],
          };
        }

        let absSession;
        try {
          absSession = validateSessionPath(session_file);
        } catch (err) {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                error: err.message,
              }, null, 2),
            }],
          };
        }

        try {
          const sessionData = JSON.parse(readFileSync(absSession, 'utf8'));
          // Merge all completed phase contexts into initialCtx
          for (const phaseName of PHASE_NAMES) {
            if (phaseName === resume_from) break; // stop at resume point
            const phaseResult = sessionData.phases?.[phaseName];
            if (phaseResult?.context) {
              // Layer each phase's context in order
              initialCtx = { ...initialCtx, ...phaseResult.context };
            }
          }
          skipBefore = resume_from;
        } catch (err) {
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                error: `Failed to read session file: ${err.message}`,
              }, null, 2),
            }],
          };
        }
      }

      // ── Session file for this run ─────────────────────────────────────────
      const sessionFile = initSession(target, agent);

      const phases = [
        { name: 'profile',    fn: runProfile },
        { name: 'audit',      fn: runAudit },
        { name: 'confirm',    fn: runConfirm },
        { name: 'assess',     fn: runAssess },
        { name: 'draft_ghsa', fn: runDraftGhsa },
        { name: 'disclose',   fn: runDisclose },
      ];

      let ctx     = initialCtx;
      const results    = {};
      const skipped    = [];
      let resumeActive = skipBefore === null; // true from the start if no resume

      for (const { name, fn } of phases) {
        // Skip phases before the resume point
        if (!resumeActive) {
          if (name === skipBefore) {
            resumeActive = true;
          } else {
            skipped.push(name);
            continue;
          }
        }

        const phaseConfig = config.phases?.[name] ?? null;
        const trimmed     = trimContext(ctx, name);
        const result      = await fn({ config, target, context: trimmed, callProvider, phaseConfig });
        writePhaseToSession(sessionFile, name, result);
        results[name] = result;
        ctx = result.context;
      }

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            session_file:      sessionFile,
            phases_completed:  Object.keys(results),
            phases_skipped:    skipped,
            resumed_from:      resume_from ?? null,
            final_context:     ctx,
            results,
          }, null, 2),
        }],
      };
    }
  );

  return server;
}
