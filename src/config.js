import { readFileSync } from 'fs';
import { resolve, relative, isAbsolute } from 'path';
import { load as yamlLoad } from 'js-yaml';

/**
 * Enforce that the resolved agent config path stays within the current working
 * directory.  Prevents path-traversal attacks where a caller supplies an `agent`
 * parameter that escapes the project root and reads arbitrary host files.
 *
 * If you need an agent config that lives outside the project (e.g. a shared
 * ~/.config/hyperdope/agent.yaml), supply it at startup via the --agent flag
 * or the HYPERDOPE_AGENT environment variable instead of a per-call parameter.
 */
function assertWithinCwd(requested, absPath) {
  const cwd = process.cwd();
  const rel = relative(cwd, absPath);
  // rel starts with '..'  → path climbs above cwd on POSIX and Windows
  // isAbsolute(rel)       → cross-drive reference on Windows (relative() returns
  //                         the abs path unchanged when drives differ)
  if (rel.startsWith('..') || isAbsolute(rel)) {
    throw new Error(
      `Agent config path must be within the working directory.\n` +
      `  Provided : ${requested}\n` +
      `  Resolved : ${absPath}\n` +
      `  CWD      : ${cwd}\n` +
      `Tip: use --agent or HYPERDOPE_AGENT to specify a config outside the project.`
    );
  }
}

function resolveEnvVars(value) {
  if (typeof value !== 'string') return value;
  return value.replace(/\$\{([^}]+)\}/g, (_, varName) => {
    const resolved = process.env[varName];
    if (resolved === undefined) {
      throw new Error(`Missing required environment variable: ${varName}`);
    }
    return resolved;
  });
}

function resolveObj(obj) {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') return resolveEnvVars(obj);
  if (Array.isArray(obj)) return obj.map(resolveObj);
  if (typeof obj === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(obj)) {
      out[k] = resolveObj(v);
    }
    return out;
  }
  return obj;
}

export function loadAgentConfig(agentPath) {
  const absPath = resolve(agentPath);
  assertWithinCwd(agentPath, absPath);
  let raw;
  try {
    raw = readFileSync(absPath, 'utf8');
  } catch {
    throw new Error(`Cannot read agent config: ${absPath}`);
  }

  const parsed = yamlLoad(raw);
  if (!parsed || typeof parsed !== 'object') {
    throw new Error(`Invalid agent config (empty or not an object): ${absPath}`);
  }

  const config = resolveObj(parsed);

  if (!config.provider) throw new Error('agent.yaml must specify a provider');
  if (!config.model) throw new Error('agent.yaml must specify a model');

  return config;
}

export function resolveAgentPath(cliFlag) {
  if (cliFlag) return cliFlag;
  if (process.env.HYPERDOPE_AGENT) return process.env.HYPERDOPE_AGENT;

  try {
    readFileSync(resolve('./agent.yaml'));
    return './agent.yaml';
  } catch {
    throw new Error(
      'No agent config found. Provide one via:\n' +
      '  --agent path/to/agent.yaml\n' +
      '  HYPERDOPE_AGENT env var\n' +
      '  ./agent.yaml in current directory'
    );
  }
}
