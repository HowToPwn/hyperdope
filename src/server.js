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
} from './phases/index.js';
import { initSession, writePhaseToSession, newSessionTimestamp, sessionPath } from './session.js';

const toolInput = z.object({
  agent: z.string().describe('Path to agent.yaml config file'),
  target: z.string().describe('Target descriptor: repo URL, domain, binary path, etc.'),
  context: z.record(z.unknown()).optional().describe('Prior phase output to resume from'),
});

function makePhaseHandler(phaseName, runFn) {
  return async ({ agent, target, context }) => {
    const config = loadAgentConfig(agent);
    const phaseConfig = config.phases?.[phaseName] ?? null;

    const result = await runFn({ config, target, context: context ?? {}, callProvider, phaseConfig });

    // Persist every individual tool call to its own session file
    const sf = sessionPath(newSessionTimestamp());
    writePhaseToSession(sf, phaseName, result);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  };
}

export function createServer() {
  const server = new McpServer({
    name: 'hyperdope',
    version: '0.1.0',
  });

  server.tool(
    'hd_profile',
    'Phase 1: Map the target attack surface — trust boundaries, parsers, deserialization, supply chain, auth flows, LLM surfaces',
    toolInput.shape,
    makePhaseHandler('profile', runProfile)
  );

  server.tool(
    'hd_audit',
    'Phase 2: Agentic vulnerability hunt — OWASP Top 10, SANS 25, LLM Top 10, reasoning per surface category',
    toolInput.shape,
    makePhaseHandler('audit', runAudit)
  );

  server.tool(
    'hd_confirm',
    'Phase 3: Generate minimal, self-contained PoC for a finding from the audit phase',
    toolInput.shape,
    makePhaseHandler('confirm', runConfirm)
  );

  server.tool(
    'hd_assess',
    'Phase 4: CVSS v3.1 scoring with chain-of-thought reasoning, CWE classification, severity label',
    toolInput.shape,
    makePhaseHandler('assess', runAssess)
  );

  server.tool(
    'hd_draft_ghsa',
    'Phase 5: Produce a GitHub Security Advisory draft following the GHSA schema',
    toolInput.shape,
    makePhaseHandler('draft_ghsa', runDraftGhsa)
  );

  server.tool(
    'hd_disclose',
    'Phase 6: Generate executive brief, full technical advisory, and vendor notification email template',
    toolInput.shape,
    makePhaseHandler('disclose', runDisclose)
  );

  server.tool(
    'hd_run',
    'Run all 6 phases sequentially: profile → audit → confirm → assess → draft_ghsa → disclose. Context is chained automatically.',
    toolInput.shape,
    async ({ agent, target, context }) => {
      const config = loadAgentConfig(agent);
      const sessionFile = initSession(target, agent);

      const phases = [
        { name: 'profile', fn: runProfile },
        { name: 'audit', fn: runAudit },
        { name: 'confirm', fn: runConfirm },
        { name: 'assess', fn: runAssess },
        { name: 'draft_ghsa', fn: runDraftGhsa },
        { name: 'disclose', fn: runDisclose },
      ];

      let ctx = context ?? {};
      const results = {};

      for (const { name, fn } of phases) {
        const phaseConfig = config.phases?.[name] ?? null;
        const result = await fn({ config, target, context: ctx, callProvider, phaseConfig });
        writePhaseToSession(sessionFile, name, result);
        results[name] = result;
        ctx = result.context;
      }

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                session_file: sessionFile,
                phases_completed: Object.keys(results),
                final_context: ctx,
                results,
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  return server;
}
