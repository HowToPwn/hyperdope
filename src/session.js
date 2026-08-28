import { mkdirSync, readFileSync, writeFileSync, existsSync, renameSync, unlinkSync } from 'fs';
import { resolve, join } from 'path';
import { randomBytes } from 'node:crypto';

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

  // Atomic write: write to temp file, then rename (rename is atomic on POSIX)
  const tmp = filePath + '.tmp.' + randomBytes(4).toString('hex');

  const existing = readSession(filePath);
  existing[phaseName] = result;
  existing._updated = new Date().toISOString();

  try {
    writeFileSync(tmp, JSON.stringify(existing, null, 2), { encoding: 'utf8', mode: 0o600 });
    renameSync(tmp, filePath);
  } catch (err) {
    // Clean up temp file on failure
    try { if (existsSync(tmp)) unlinkSync(tmp); } catch {}
    throw err;
  }
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
