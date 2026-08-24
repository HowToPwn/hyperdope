import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
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
} from './phases/index.js';
import { initSession, writePhaseToSession, newSessionTimestamp, sessionPath } from './session.js';
import { trimContext } from './context.js';

const toolInput = z.object({
  agent:   z.string().describe('Path to agent.yaml config file'),
  target:  z.string().describe('Target descriptor: repo URL, domain, binary path, etc.'),
  context: z.record(z.unknown()).optional().describe('Prior phase output to resume from'),
});

const scanInput = z.object({
  target:  z.string().describe('Directory path containing lockfiles (package-lock.json, requirements.txt, go.mod)'),
  context: z.record(z.unknown()).optional().describe('Prior phase output to merge into scan context'),
});

function makePhaseHandler(phaseName, runFn) {
  return async ({ agent, target, context }) => {
    const config = loadAgentConfig(agent);
    const phaseConfig = config.phases?.[phaseName] ?? null;

    const trimmed = trimContext(context ?? {}, phaseName);
    const result = await runFn({ config, target, context: trimmed, callProvider, phaseConfig });

    // Persist individual tool calls to their own session file
    const sf = sessionPath(newSessionTimestamp());
    writePhaseToSession(sf, phaseName, result);

    return {
      content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
    };
  };
}

export function createServer() {
  const server = new McpServer({
    name: 'hyperdope',
    version: '0.1.0',
  });

  server.tool(
    'hd_scan',
    'Phase 0: Scan dependencies against OSV.dev CVE database — no API key required. Supports npm (package.json/package-lock.json), Python (requirements.txt), Go (go.mod)',
    scanInput.shape,
    async ({ target, context }) => {
      const result = await runScan({ target, context: context ?? {} });
      const sf = sessionPath(newSessionTimestamp());
      writePhaseToSession(sf, 'scan', result);
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    'hd_profile',
    'Phase 1: Map the target attack surface — STRIDE threat model, data flows, trust boundaries, parsers, deserialization, supply chain, auth flows, LLM surfaces',
    toolInput.shape,
    makePhaseHandler('profile', runProfile)
  );

  server.tool(
    'hd_audit',
    'Phase 2: 5-step adversarial vulnerability hunt — entry point inventory, source→sink tracing, control gap analysis, assumption violation, chain candidates. OWASP Top 10, SANS 25, LLM Top 10.',
    toolInput.shape,
    makePhaseHandler('audit', runAudit)
  );

  server.tool(
    'hd_confirm',
    'Phase 3: Generate up to 3 PoCs ordered by exploitability, with reliability rating and detection likelihood',
    toolInput.shape,
    makePhaseHandler('confirm', runConfirm)
  );

  server.tool(
    'hd_assess',
    'Phase 4: CVSS v3.1 scoring with per-metric chain-of-thought; score verified mathematically from the vector string — LLM cannot hallucinate the number',
    toolInput.shape,
    makePhaseHandler('assess', runAssess)
  );

  server.tool(
    'hd_draft_ghsa',
    'Phase 5: GitHub Security Advisory draft (GHSA schema), remediation priority P1/P2/P3, disclosure readiness checklist',
    toolInput.shape,
    makePhaseHandler('draft_ghsa', runDraftGhsa)
  );

  server.tool(
    'hd_disclose',
    'Phase 6: Coordinated disclosure package — executive brief, full technical advisory with IoCs and remediation, vendor notification email with 90-day timeline table',
    toolInput.shape,
    makePhaseHandler('disclose', runDisclose)
  );

  server.tool(
    'hd_run',
    'Run all 6 LLM phases sequentially (profile → audit → confirm → assess → draft_ghsa → disclose) with automatic context chaining and trimming',
    toolInput.shape,
    async ({ agent, target, context }) => {
      const config = loadAgentConfig(agent);
      const sessionFile = initSession(target, agent);

      const phases = [
        { name: 'profile',    fn: runProfile },
        { name: 'audit',      fn: runAudit },
        { name: 'confirm',    fn: runConfirm },
        { name: 'assess',     fn: runAssess },
        { name: 'draft_ghsa', fn: runDraftGhsa },
        { name: 'disclose',   fn: runDisclose },
      ];

      let ctx = context ?? {};
      const results = {};

      for (const { name, fn } of phases) {
        const phaseConfig = config.phases?.[name] ?? null;
        const trimmed = trimContext(ctx, name);
        const result = await fn({ config, target, context: trimmed, callProvider, phaseConfig });
        writePhaseToSession(sessionFile, name, result);
        results[name] = result;
        ctx = result.context;
      }

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            session_file: sessionFile,
            phases_completed: Object.keys(results),
            final_context: ctx,
            results,
          }, null, 2),
        }],
      };
    }
  );

  return server;
}
