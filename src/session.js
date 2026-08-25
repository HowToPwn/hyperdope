import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'fs';
import { resolve, join } from 'path';

const SESSIONS_DIR = resolve('.hyperdope/sessions');

export function sessionPath(timestamp) {
  return join(SESSIONS_DIR, `${timestamp}.json`);
}

export function newSessionTimestamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

export function readSession(filePath) {
  if (!existsSync(filePath)) return {};
  try {
    return JSON.parse(readFileSync(filePath, 'utf8'));
  } catch {
    return {};
  }
}

export function writePhaseToSession(filePath, phaseName, result) {
  mkdirSync(SESSIONS_DIR, { recursive: true, mode: 0o700 });

  const existing = readSession(filePath);
  existing[phaseName] = result;
  existing._updated = new Date().toISOString();

  writeFileSync(filePath, JSON.stringify(existing, null, 2), { encoding: 'utf8', mode: 0o600 });
}

export function initSession(target, agentPath) {
  mkdirSync(SESSIONS_DIR, { recursive: true, mode: 0o700 });
  const ts = newSessionTimestamp();
  const fp = sessionPath(ts);
  const data = {
    _created: new Date().toISOString(),
    _updated: new Date().toISOString(),
    _target: target,
    _agent: agentPath,
  };
  writeFileSync(fp, JSON.stringify(data, null, 2), { encoding: 'utf8', mode: 0o600 });
  return fp;
}
