# AGENT FIX PROMPT — HowToPwn/hyperdope

## Context

You are fixing the source code of `https://github.com/HowToPwn/hyperdope` — an MCP server for adversarial security research. The repo has been cloned locally. All fixes must be made in-place on the cloned files. Do NOT refactor logic that isn't listed below.

---

## ISSUES TO FIX (ordered by severity)

---

### [CRITICAL-1] `src/internal/config-loader.js` — Path Traversal + Prototype Pollution

**File:** `src/internal/config-loader.js`  
**Severity:** High (CVSS 7.3) — HD-CVE-2026-0052 / CWE-706 / CWE-829  
**Tracked as:** HD-INFRA-519

**Problem A — Path Traversal:**  
`HD_INTERNAL_CONFIG` env var is passed to `path.resolve()` then directly to `readFileSync()` with no check that the result stays within `process.cwd()`. An attacker with env injection can read arbitrary files (e.g. `/proc/self/environ`).

**Problem B — Prototype Pollution:**  
`fileOverrides = JSON.parse(raw)` then `{ ...DEFAULTS, ...fileOverrides }` — a JSON payload with `"__proto__"` as a key will pollute `Object.prototype` through the spread.

**Fix required:**

```js
// A: After resolving configPath, enforce it stays within cwd:
const cwd = process.cwd();
const rel = path.relative(cwd, configPath);
if (rel.startsWith('..') || path.isAbsolute(rel)) {
  process.stderr.write('[config-loader] WARN: HD_INTERNAL_CONFIG outside cwd — ignoring\n');
  // fall back to DEFAULTS only, do not load the file
}

// B: Use a null-prototype guard before spread:
const raw = readFileSync(configPath, 'utf8');
const parsed = JSON.parse(raw);
// Strip prototype-polluting keys
const fileOverrides = Object.assign(Object.create(null), parsed);
for (const k of ['__proto__', 'constructor', 'prototype']) delete fileOverrides[k];
const merged = { ...DEFAULTS, ...fileOverrides };
```

---

### [CRITICAL-2] `src/internal/vault-bridge.js` — SSRF + TLS Bypass via `HD_VAULT_ADDR`

**File:** `src/internal/vault-bridge.js`  
**Severity:** High (CVSS 7.4) — HD-CVE-2026-0049 / CWE-295 / CWE-918  
**Tracked as:** HD-INFRA-521

**Problem:**  
`vault_addr` from config (sourced from `HD_VAULT_ADDR`) is embedded directly in fetch URL with no scheme/host validation. Combined with `vault_tls_verify=false`, an attacker can SSRF to internal endpoints (e.g. AWS IMDS `169.254.169.254`) or MITM the vault connection.

**Fix required:**

```js
// In _vaultUrl(), validate scheme before building URL:
function _vaultUrl(secretPath) {
  const raw = config.vault_addr.replace(/\/$/, '');
  let parsed;
  try { parsed = new URL(raw); } catch {
    throw new Error('[vault-bridge] Invalid vault_addr — not a valid URL');
  }
  if (!['https:', 'http:'].includes(parsed.protocol)) {
    throw new Error(`[vault-bridge] vault_addr must use http(s): scheme, got ${parsed.protocol}`);
  }
  // In production, enforce https only
  if (process.env.NODE_ENV === 'production' && parsed.protocol !== 'https:') {
    throw new Error('[vault-bridge] vault_addr must use https in production');
  }
  const mount  = config.vault_mount;
  const prefix = config.vault_path_prefix;
  return `${raw}/v1/${mount}/data/${prefix}/${secretPath}`;
}

// Remove or restrict vault_tls_verify=false in _buildFetchInit():
// Only allow TLS bypass if NODE_ENV !== 'production' AND explicit opt-in
if (!config.vault_tls_verify && process.env.NODE_ENV !== 'production') {
  // allow with warning (already logs)
} else if (!config.vault_tls_verify) {
  throw new Error('[vault-bridge] vault_tls_verify=false is not permitted in production');
}
```

---

### [HIGH-1] `src/internal/auth-bridge.js` — JWT Expiry Skip Propagation (HD-CVE-2026-0047)

**File:** `src/internal/auth-bridge.js`  
**Severity:** High (CVSS 8.2) — CWE-287 / CWE-345  
**Tracked as:** HD-INFRA-515

**Problem:**  
`verifyToken(token, { skipExpiry: true })` bypasses JWT `exp` validation. There is no enforcement that only `session-manager.js:hydrateSession()` may pass this option. If any tool handler ever passes unvalidated `opts` from a user-controlled parameter, this becomes an LLM-controllable auth bypass.

**Fix required:**  
Add a caller identity check using a private Symbol or a module-local token rather than a plain boolean in the public opts:

```js
// In auth-bridge.js — replace the boolean with a module-local capability token:
const _SKIP_EXPIRY_TOKEN = Symbol('hyperdope.skipExpiry');
export { _SKIP_EXPIRY_TOKEN }; // only importable by session-manager

// In verifyToken:
if (opts.skipExpiry !== _SKIP_EXPIRY_TOKEN && payload.exp && now > payload.exp) {
  throw new Error('[auth-bridge] Token expired');
}

// In session-manager.js — import the Symbol and use it:
import { verifyToken, _SKIP_EXPIRY_TOKEN } from './auth-bridge.js';
// ...
const payload = verifyToken(accessToken, { skipExpiry: _SKIP_EXPIRY_TOKEN });
```

This ensures `skipExpiry` cannot be triggered by passing `{ skipExpiry: true }` from external code.

---

### [HIGH-2] `src/internal/token-vault.js` — MWK Retained in Process Memory (HD-CVE-2026-0050)

**File:** `src/internal/token-vault.js`  
**Severity:** Medium (CVSS 6.5) — CWE-312 / CWE-200  
**Tracked as:** HD-INFRA-518

**Problem:**  
`_mwk` (Master Wrapping Key) is stored as a module-level variable for the entire process lifetime. A heap dump or `/proc/PID/mem` read exposes it, enabling decryption of all keyring envelopes.

**Fix required (software-only mitigation until HSM is available):**  
Zero the MWK buffer after unsealing all slots, and re-fetch on demand if a slot requires decryption with the MWK again. Change `initKeyring()` to:

```js
export async function initKeyring() {
  if (_activeSlotId) return;           // already initialised (MWK may be zeroed)

  await resolveVaultCredential();
  const mwkData = await vaultRead('keyring/master-wrapping-key');
  if (!mwkData?.mwk_hex || mwkData.mwk_hex.length !== 64) {
    throw new Error('[token-vault] MWK missing or malformed in Vault');
  }

  const mwk = Buffer.from(mwkData.mwk_hex, 'hex');

  // Load all slots and immediately unseal them while we have the MWK
  const slotsData = await vaultRead('keyring/slots');
  for (const slot of slotsData.slots) {
    // (store sealed envelopes as before)
    _keyring.set(slot.id, { ...slot_record });
  }
  _activeSlotId = slotsData.active_slot_id;

  // Zero MWK after use — do NOT retain it in module scope
  mwk.fill(0);
  // _mwk remains null — getSigningKey must re-fetch from Vault if needed
}
```

Update `getSigningKey()` to re-fetch MWK on demand if `_mwk` is null (or design as a short-lived local variable per call).

---

### [MEDIUM-1] `src/internal/session-manager.js` — Refresh Token Not Rotated (HD-CVE-2026-0051)

**File:** `src/internal/session-manager.js`  
**Severity:** Medium (CVSS 5.9) — CWE-613 / CWE-384  
**Tracked as:** HD-INFRA-516

**Problem:**  
`refreshSession()` issues a new access token but does not rotate the refresh token. A stolen refresh token stays valid until `session.expiresAt`.

**Fix required:**  
Rotate the refresh token on every successful use:

```js
export function refreshSession(sessionId, refreshToken) {
  const session = _sessions.get(sessionId);
  if (!session) throw new Error('[session-manager] Session not found');

  if (!safeCompare(refreshToken, session.refreshToken)) {
    throw new Error('[session-manager] Refresh token mismatch');
  }

  if (Date.now() > session.expiresAt) {
    _sessions.delete(sessionId);
    throw new Error('[session-manager] Session expired — re-authenticate');
  }

  hydrateSession(session.accessToken, { allowExpiredToken: true });

  const newAccessToken  = issueToken({ sub: session.sub, hd_sid: session.id, hd_scope: session.scope });
  const newRefreshToken = secureRandom(32).toString('base64url'); // ROTATE HERE

  session.accessToken  = newAccessToken;
  session.refreshToken = newRefreshToken;   // replace old token
  session.lastSeenAt   = Date.now();

  return { accessToken: newAccessToken, refreshToken: newRefreshToken, expiresAt: session.expiresAt };
}
```

---

### [MEDIUM-2] `src/internal/crypto-primitives.js` — Timing Oracle in `safeCompare()` (HD-CVE-2026-0053)

**File:** `src/internal/crypto-primitives.js`  
**Severity:** Low (CVSS 3.7) — CWE-208  
**Tracked as:** HD-INFRA-520

**Problem:**  
`safeCompare()` returns `false` early (O(1)) when buffer lengths differ, before `timingSafeEqual()` runs. This leaks length information. Currently unexploitable for HMAC digests (fixed length), but a latent code quality issue for future callers.

**Fix required:**  
Pad both inputs to `max(len(a), len(b))` before calling `timingSafeEqual()`:

```js
export function safeCompare(a, b) {
  const bufA = Buffer.isBuffer(a) ? a : Buffer.from(String(a));
  const bufB = Buffer.isBuffer(b) ? b : Buffer.from(String(b));
  const len  = Math.max(bufA.length, bufB.length);
  const padA = Buffer.concat([bufA, Buffer.alloc(len - bufA.length)]);
  const padB = Buffer.concat([bufB, Buffer.alloc(len - bufB.length)]);
  // Length difference itself still leaks via the original lengths being in JS scope,
  // but timingSafeEqual now always runs O(n) regardless of length match.
  const equal = timingSafeEqual(padA, padB);
  return equal && bufA.length === bufB.length; // both conditions required
}
```

---

### [LOW-1] `src/phases/scan.js` — No Path Validation on `target` Parameter

**File:** `src/phases/scan.js`  
**Severity:** Low-Medium — CWE-22 (Path Traversal)

**Problem:**  
`runScan({ target })` calls `resolve(target)` but does NOT verify the result stays within `process.cwd()`. The `server.js` properly validates `session_file` with `validateSessionPath()` and validates `agent` with `assertWithinCwd()`, but `hd_scan`'s `target` has no such guard. An MCP caller can pass `../../../etc` as the target directory.

**Fix required:**  
Add a CWD-boundary check in `runScan()` before `const dir = resolve(target)`:

```js
export async function runScan({ target, context = {} }) {
  const dir = resolve(target);
  const cwd = process.cwd();
  const rel = relative(cwd, dir);
  if (rel.startsWith('..') || isAbsolute(rel)) {
    throw new Error(`[hd_scan] target path must be within the working directory: "${target}"`);
  }
  // ... rest of function
}
```

Add `relative` and `isAbsolute` to the `import` statement at the top of the file.

---

### [LOW-2] `src/providers/claude.js` — Leftover Debug Comment

**File:** `src/providers/claude.js`  
**Severity:** Low (code quality)

**Problem:**  
Line 16 contains `//dummy text` — a leftover debug/placeholder comment that has no purpose and should not be in production code.

**Fix required:**  
Delete the `//dummy text` comment on line 16.

---

### [LOW-3] `README.md` — Wrong Clone URL

**File:** `README.md`  
**Severity:** Low (documentation bug)

**Problem:**  
The "Dev / local" install section contains:
```
git clone https://github.com/your-org/hyperdope.git
```
`your-org` is a placeholder that was never replaced with the real org (`HowToPwn`).

**Fix required:**  
Replace:
```
git clone https://github.com/your-org/hyperdope.git
```
With:
```
git clone https://github.com/HowToPwn/hyperdope.git
```

---

### [LOW-4] `notepad.txt` — Sensitive Internal Dev Notes Committed to Public Repo

**File:** `notepad.txt`  
**Severity:** Medium (information disclosure)

**Problem:**  
`notepad.txt` contains internal npm publish workflow instructions including the npm account username (`uziii2208`) and auth configuration details. This file is already excluded from the npm package via `.gitignore`-equivalent in `package.json`'s `files` array, but it is **publicly visible in the git repo** on GitHub.

**Fix required:**
1. Delete `notepad.txt` from the repository.
2. Add `notepad.txt` to `.gitignore`.
3. If the file has been in git history, consider a `git filter-repo` purge or create a new commit removing it.

---

### [INFO-1] `src/internal/README.internal.md` — Security TODOs Reference Non-Existent Static Secrets

**File:** `src/internal/README.internal.md`  
**Severity:** Informational

**Problem:**  
The TODO table references `BOOTSTRAP_SIGNING_KEY`, `VAULT_TOKEN_FALLBACK`, `VAULT_TOKEN_OVERRIDE`, `SESSION_SECRET`, `INTERNAL_ADMIN_KEY`, and `DEFAULTS` audit — but these static hardcoded fallback values do not appear in the current committed source. This suggests either they were cleaned from source but the TODO tracking wasn't updated, or they exist in an uncommitted/runtime-injected layer.

**Fix required:**  
Audit whether these constants exist in any build artifact or deployment secret. Update the TODO table to reflect current state. If they were already removed, mark those tickets as RESOLVED.

---

## SUMMARY TABLE

| ID | File | Type | Severity | Action |
|----|------|------|----------|--------|
| CRITICAL-1 | `src/internal/config-loader.js` | Path traversal + prototype pollution | High | Fix path check + null-proto guard |
| CRITICAL-2 | `src/internal/vault-bridge.js` | SSRF + TLS bypass | High | Add scheme allowlist + production TLS enforcement |
| HIGH-1 | `src/internal/auth-bridge.js` | Auth bypass via skipExpiry | High | Replace bool opt with private Symbol |
| HIGH-2 | `src/internal/token-vault.js` | MWK in memory | Medium | Zero MWK after use |
| MEDIUM-1 | `src/internal/session-manager.js` | Refresh token not rotated | Medium | Rotate on every refresh call |
| MEDIUM-2 | `src/internal/crypto-primitives.js` | Timing oracle in safeCompare | Low | Pad-then-compare |
| LOW-1 | `src/phases/scan.js` | No CWD boundary check on target | Low-Medium | Add assertWithinCwd equivalent |
| LOW-2 | `src/providers/claude.js` | `//dummy text` leftover comment | Low | Delete line |
| LOW-3 | `README.md` | Wrong clone URL placeholder | Low | Replace `your-org` → `HowToPwn` |
| LOW-4 | `notepad.txt` | Sensitive dev notes in public repo | Medium | Delete file + add to .gitignore |
| INFO-1 | `src/internal/README.internal.md` | Stale TODO table | Info | Reconcile with actual code state |

---

## CONSTRAINTS FOR THE AGENT

1. **Do not touch** `src/phases/{profile,audit,confirm,assess,draft_ghsa,disclose,verify}.js` — these contain prompt logic and must not be modified.
2. **Do not touch** `src/server.js` unless the LOW-1 fix requires adding an import to `scan.js` that changes the server's tool registration (it should not).
3. **Do not change** any public tool API signatures (`hd_scan`, `hd_run`, etc.) — only internal behavior changes.
4. After making all fixes, run:
   ```bash
   npm test
   node --check src/phases/scan.js src/internal/config-loader.js src/internal/vault-bridge.js src/internal/auth-bridge.js src/internal/crypto-primitives.js src/internal/session-manager.js src/internal/token-vault.js
   ```
   and confirm all pass before committing.
5. Each fix should be a **separate commit** with a message referencing the issue ID (e.g. `fix(config-loader): path traversal + prototype pollution [CRITICAL-1, HD-CVE-2026-0052]`).
