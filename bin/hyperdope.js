#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createServer } from '../src/server.js';
import { resolveAgentPath } from '../src/config.js';

// MCP server speaks JSON-RPC over stdio only — no console output except through the protocol
const args = process.argv.slice(2);

const agentFlagIdx = args.indexOf('--agent');
const agentFlag = agentFlagIdx !== -1 ? args[agentFlagIdx + 1] : null;

// Validate agent path at startup so errors surface immediately
try {
  resolveAgentPath(agentFlag);
} catch {
  // Don't crash — agent path may be passed per-call in tool arguments
}

const server = createServer();
const transport = new StdioServerTransport();

await server.connect(transport);
