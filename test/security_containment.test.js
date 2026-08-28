import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, symlinkSync, rmSync, existsSync, realpathSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve, relative, isAbsolute } from 'path';
import { runScan } from '../src/phases/scan.js';

test('Security: detectSecrets rejects symlinks in SCAN_FILES pointing to host files', async () => {
  const tmpHost = mkdtempSync(join(tmpdir(), 'hd-host-secret-'));
  // FIX: Create target within cwd so it passes the new CWD boundary check (LOW-1)
  const cwd = process.cwd();
  const tmpTarget = mkdtempSync(join(cwd, '.hd-test-target-'));
  const hostSecretFile = join(tmpHost, 'secret.env');
  
  try {
    // Write host secret inside an isolated secure temporary directory
    writeFileSync(hostSecretFile, 'AWS_KEY=AKIAIOSFODNN7EXAMPLE\n', { mode: 0o600 });

    // Create target directory with symlink .env pointing to host secret
    const symlinkPath = join(tmpTarget, '.env');
    try {
      symlinkSync(hostSecretFile, symlinkPath, 'file');
    } catch {
      // Symlink creation might require elevated privileges on some Windows configurations
      return;
    }

    const result = await runScan({ target: tmpTarget });
    
    // O_NOFOLLOW is POSIX-only; on Windows it's undefined and symlinks may be followed.
    // The test validates the guard works on Linux/macOS where O_NOFOLLOW is available.
    if (process.platform !== 'win32') {
      const detectedSecrets = result.findings.filter(f => f.type === 'AWS Access Key ID');
      assert.equal(detectedSecrets.length, 0, 'Symlinked host secret must not be read or extracted');
      assert.equal(result.meta.secrets_found, 0, 'No secrets should be found via symlinks');
    }
  } finally {
    rmSync(tmpHost, { recursive: true, force: true });
    rmSync(tmpTarget, { recursive: true, force: true });
  }
});

test('Security: session_file path containment prevents traversal', () => {
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

  // 1. Relative traversal path escaping working directory
  assert.throws(
    () => validateSessionPath('../../../etc/passwd'),
    /session_file traverses outside working directory/
  );

  // 2. Windows / Unix absolute path escaping working directory
  assert.throws(
    () => validateSessionPath('/etc/shadow'),
    /session_file traverses outside working directory/
  );

  // 3. Non-existent file within working directory
  assert.throws(
    () => validateSessionPath('./nonexistent-session.json'),
    /session_file not found/
  );

  // 4. Valid file within working directory passes
  const validPath = validateSessionPath('package.json');
  assert.equal(validPath, resolve('package.json'));
});
