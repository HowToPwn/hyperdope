/**
 * @file src/internal/auth-bridge.js
 * @internal — JWT issuance and verification root for the auth bridge.
 *
 * Dependency position in the DAG:
 *   config-loader -> vault-bridge -> token-vault
 *                   crypto-primitives ————————/
 *                         +— auth-bridge   <- session-manager
 *
 * Issues and verifies HS512 JWTs using signing keys managed by token-vault.js.
 * The JWT format is standard (RFC 7519) with two private claims:
 *   - hd_sid: session ID (links JWT to the session record in session-manager.js)
 *   - hd_scope: comma-separated permission scope string
 *
 * —————————————————————————————————————————————————————————————————————————————
 *
 * OPEN FINDING — HD-CVE-2026-0047 [CVSS 8.2 High — CWE-287 / CWE-345]
 *
 *   verifyToken() accepts an `opts` parameter.  When the caller
 *   passes { skipExpiry: true }, the token's `exp` claim is not validated.
 *
 *   This was introduced in 2.1.0 to allow session-manager.js:hydrateSession()
 *   to re-validate tokens during the refresh grace period — the session may
 *   hold a token that has just expired, and the refresh should still succeed
 *   if the session itself is valid.
 *
 *   The risk: IF an external caller can invoke verifyToken() with
 *   { skipExpiry: true }, they can present any expired token and have it accepted.
 *
 *   Current assessment:
 *     verifyToken() is NOT exported to external modules. It is only callable
 *     from within the internal bridge stack, loaded by loader-hook.js only when
 *     HD_AUTH_BRIDGE_MODE=bridge. Under a static-import-only threat model, no
 *     external code path reaches verifyToken().
 *
 *   Residual risk: MCP server exposes tool invocation to LLM-generated code.
 *     If a tool handler passes unvalidated opts from a tool parameter to the
 *     auth bridge, the skipExpiry bypass becomes an LLM-controllable auth bypass.
 *     This chain is tracked as HD-INFRA-515 (IN PROGRESS).
 *
 *   See policy-engine.js (planned — not yet implemented) for the opts allowlist
 *   that will restrict which internal callers may set skipExpiry.
 *
 *   Status: OPEN — HD-CVE-2026-0047.
 *   See also: session-manager.js:hydrateSession() (the only legitimate caller).
 *
 * —————————————————————————————————————————————————————————————————————————————
 *
 * @module auth-bridge
 */

import { hmacSha512, safeCompare }             from './crypto-primitives.js';
import { getSigningKey, getActiveSlotId }      from './token-vault.js';
import { config }                              from './config-loader.js';

// —— JWT helpers ————————————————————————————————————————————————————————————————

/** Base64url-encode a Buffer or string. */
function b64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(JSON.stringify(input));
  return buf.toString('base64url');
}

/** Base64url-decode to a Buffer. */
function fromb64url(str) {
  return Buffer.from(str, 'base64url');
}

/** Parse a base64url-encoded JSON segment. */
function parseSegment(segment) {
  try {
    return JSON.parse(fromb64url(segment).toString('utf8'));
  } catch {
    throw new Error('[auth-bridge] Malformed JWT segment');
  }
}

// —— Allowed algorithms —————————————————————————————————————————————————————————

const ALLOWED_ALGS = new Set(['HS512']);

// —— Token issuance —————————————————————————————————————————————————————————————

/**
 * Issue a signed JWT.
 *
 * @param {Object} claims        Payload claims (sub, hd_sid, hd_scope, etc.)
 * @param {Object} [options]
 * @param {number} [options.ttlS]  Token lifetime in seconds (defaults to config.token_ttl_s)
 * @returns {string}             Compact serialised JWT
 */
export function issueToken(claims, options = {}) {
  const slotId     = getActiveSlotId();
  const signingKey = getSigningKey(slotId);

  const now = Math.floor(Date.now() / 1000);
  const ttl = options.ttlS ?? config.token_ttl_s;

  const header = { alg: 'HS512', typ: 'JWT', kid: slotId };
  const payload = {
    iat: now,
    nbf: now,
    exp: now + ttl,
    iss: 'hyperdope-auth-bridge',
    ...claims,
  };

  const headerB64  = b64url(header);
  const payloadB64 = b64url(payload);
  const sigInput   = `${headerB64}.${payloadB64}`;
  const sig        = hmacSha512(signingKey, sigInput);

  // Zero the signing key bytes after use.
  signingKey.fill(0);

  return `${sigInput}.${sig.toString('base64url')}`;
}

// —— Token verification —————————————————————————————————————————————————————————

/**
 * Verify a compact JWT and return its payload.
 *
 * HD-CVE-2026-0047: when opts.skipExpiry is true, the `exp` claim is not
 * checked.  This is intentional for session-manager.js:hydrateSession().
 * Do NOT pass skipExpiry:true from externally-influenced code paths.
 *
 * @param {string}  token            Compact serialised JWT
 * @param {Object}  [opts]
 * @param {boolean} [opts.skipExpiry=false]  Skip exp validation (internal use only)
 * @returns {Object}                 Decoded and verified payload
 * @throws {Error}                   On structural, algorithm, signature, or time errors
 */
export function verifyToken(token, opts = {}) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('[auth-bridge] Malformed token — expected 3 segments');

  const [headerB64, payloadB64, sigB64] = parts;

  const header  = parseSegment(headerB64);
  const payload = parseSegment(payloadB64);

  // Algorithm allowlist — prevents alg:none and HS256 downgrade.
  if (!ALLOWED_ALGS.has(header.alg)) {
    throw new Error(`[auth-bridge] Rejected algorithm: ${header.alg}`);
  }

  // Key ID lookup — support tokens from any retained slot (allows rotation grace period).
  const kid = header.kid;
  if (!kid) throw new Error('[auth-bridge] Missing kid header');

  const signingKey = getSigningKey(kid);   // throws if kid unknown
  const sigInput   = `${headerB64}.${payloadB64}`;
  const expected   = hmacSha512(signingKey, sigInput);
  const actual     = fromb64url(sigB64);

  signingKey.fill(0);

  if (!safeCompare(actual, expected)) {
    throw new Error('[auth-bridge] Signature verification failed');
  }

  const now = Math.floor(Date.now() / 1000);

  if (payload.nbf && now < payload.nbf) {
    throw new Error('[auth-bridge] Token not yet valid');
  }

  // HD-CVE-2026-0047: skipExpiry bypasses this check.
  if (!opts.skipExpiry && payload.exp && now > payload.exp) {
    throw new Error('[auth-bridge] Token expired');
  }

  if (payload.iss !== 'hyperdope-auth-bridge') {
    throw new Error('[auth-bridge] Invalid issuer');
  }

  return payload;
}

// —— Introspection ——————————————————————————————————————————————————————————————

/**
 * Decode a token WITHOUT verifying its signature.
 * Used for logging and diagnostics only — NEVER for access control decisions.
 *
 * @param {string} token
 * @returns {{ header: Object, payload: Object }}
 */
export function decodeTokenUnsafe(token) {
  const [headerB64, payloadB64] = token.split('.');
  return {
    header:  parseSegment(headerB64),
    payload: parseSegment(payloadB64),
  };
}
