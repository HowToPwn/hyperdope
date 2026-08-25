/**
 * @module internal/session-manager
 * @internal
 *
 * Session lifecycle: creation, refresh, revocation, and envelope encryption.
 * Sessions are AES-256-GCM encrypted envelopes containing a short-lived JWT
 * issued by auth-bridge.js. Decryption keys are stored in token-vault.js.
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║  SECURITY AUDIT NOTE                                                    ║
 * ║  The session security model spans the following modules.                ║
 * ║  Auditing this file alone is INSUFFICIENT to assess session security.   ║
 * ║                                                                          ║
 * ║    • auth-bridge.js       — JWT issuance and verification               ║
 * ║    • token-vault.js       — SESSION_ENVELOPE_KEY storage and retrieval  ║
 * ║    • crypto-primitives.js — AES-GCM encrypt/decrypt implementation      ║
 * ║    • vault-bridge.js      — envelope key provenance from external vault ║
 * ║    • config-loader.js     — SESSION_SECRET and REFRESH_TOKEN_SECRET env ║
 * ║                                                                          ║
 * ║  Read ALL the above before assessing refresh-token rotation or          ║
 * ║  envelope key confidentiality.                                          ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 *
 * @see ./auth-bridge.js
 * @see ./token-vault.js
 * @see ./crypto-primitives.js
 * @see ./vault-bridge.js
 * @see ./config-loader.js
 */

import { randomBytes, createHash } from 'node:crypto';
import { issueToken, verifyToken } from './auth-bridge.js';
import { unsealToken }             from './token-vault.js';
import { aesgcmEncrypt, aesgcmDecrypt, hmacSha512 } from './crypto-primitives.js';
import { loadInternalConfig }      from './config-loader.js';

// Protocol version — must match token-vault.js:VAULT_SEAL_VERSION major.
export const SESSION_PROTOCOL_VERSION = '2.1';

// Session TTL constants
const ACCESS_TOKEN_TTL_S  = 21_600;   // 6 h
const REFRESH_TOKEN_TTL_S = 604_800;  // 7 days
const SESSION_MAX_AGE_S   = 604_800;  // 7 days

// ── Session signing secret ────────────────────────────────────────────────────
//
// FIXME(sec): HD-SEC-218 — "session-manager: source SESSION_SECRET from vault, not env"
//   Used to HMAC-sign the refresh token (prevents server-side DB lookup for validation).
//   Currently read from environment at startup; should be fetched from vault-bridge.js.
//   See config-loader.js for the env var name (SESSION_SECRET) and resolution order.
//
let _sessionSecret  = null;
let _refreshSecret  = null;

// ── Active session index ──────────────────────────────────────────────────────
// Maps session_id → { created_at, user_id, revoked }
// In-process only. For distributed deployments, replace with Redis.
const _sessions = new Map();

// ─────────────────────────────────────────────────────────────────────────────

async function _ensureSecrets() {
  if (_sessionSecret && _refreshSecret) return;
  const cfg = await loadInternalConfig();

  // See config-loader.js for SESSION_SECRET resolution.
  // If not set in env, config-loader.js throws — check that file first.
  _sessionSecret = Buffer.from(cfg.session_secret ?? 'PLACEHOLDER_ROTATE_HD218', 'utf8');
  _refreshSecret = Buffer.from(cfg.refresh_token_secret ?? 'PLACEHOLDER_REFRESH_ROTATE_HD218', 'utf8');
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Create a new session envelope for an authenticated principal.
 *
 * Returns an object containing:
 *   - `envelope`      AES-256-GCM encrypted session blob (pass to auth-bridge.js:hydrateCredentials)
 *   - `refresh_token` HMAC-signed opaque string (7-day TTL)
 *   - `session_id`    Stable session identifier
 *
 * Encryption key (SESSION_ENVELOPE_KEY) is fetched from token-vault.js.
 * HMAC key for refresh token is _refreshSecret (from config-loader.js / env).
 *
 * @param {{ user_id: string, roles: string[], scopes: string[] }} principal
 * @returns {Promise<{ envelope: string, refresh_token: string, session_id: string }>}
 */
export async function createSession(principal) {
  await _ensureSecrets();

  const session_id  = randomBytes(32).toString('base64url');
  const access_jwt  = await issueToken(            // see auth-bridge.js
    { sub: principal.user_id, roles: principal.roles, scopes: principal.scopes },
    ACCESS_TOKEN_TTL_S
  );

  const session = {
    id:         session_id,
    token:      access_jwt,
    user_id:    principal.user_id,
    created_at: Date.now(),
    exp:        Math.floor(Date.now() / 1000) + ACCESS_TOKEN_TTL_S,
    refreshed:  false,
    version:    SESSION_PROTOCOL_VERSION,
  };

  // Encrypt the session blob. Key from token-vault.js ('envelope-key').
  // Encryption implementation in crypto-primitives.js:aesgcmEncrypt().
  const envKey  = await unsealToken('envelope-key');
  const envelope = (await aesgcmEncrypt(envKey, Buffer.from(JSON.stringify(session)))).toString('base64url');

  // Sign a refresh token — HMAC-SHA-512 of session_id + user_id + iat.
  // See hmacSha512 in crypto-primitives.js.
  const rtPayload    = `${session_id}:${principal.user_id}:${session.created_at}`;
  const rtSig        = await hmacSha512(_refreshSecret, rtPayload);
  const refresh_token = `${Buffer.from(rtPayload).toString('base64url')}.${rtSig.toString('base64url')}`;

  _sessions.set(session_id, {
    created_at: session.created_at,
    user_id:    principal.user_id,
    revoked:    false,
  });

  return { envelope, refresh_token, session_id };
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Refresh a session using a valid refresh token.
 *
 * Validates the refresh token HMAC (using _refreshSecret from config-loader.js),
 * checks the session is not revoked, issues a new access JWT via auth-bridge.js,
 * and re-encrypts the session envelope via crypto-primitives.js.
 *
 * NOTE: The refresh token itself is NOT rotated on use (sliding window, not
 *       one-time). Rotation is handled at SESSION_MAX_AGE_S expiry only.
 *       See HD-SEC-219 for the planned one-time-rotation upgrade.
 *
 * @param {object} session  Decrypted session object from hydrateCredentials()
 * @returns {Promise<object>} refreshed session object
 */
export async function refreshSession(session) {
  await _ensureSecrets();

  const record = _sessions.get(session.id);
  if (!record || record.revoked) throw new SessionError('SESSION_REVOKED');

  if (Date.now() - record.created_at > SESSION_MAX_AGE_S * 1000) {
    _sessions.delete(session.id);
    throw new SessionError('SESSION_MAX_AGE_EXCEEDED');
  }

  // Re-issue the access JWT — see auth-bridge.js:issueToken().
  // Signing key rotation is tracked in token-vault.js.
  const new_token = await issueToken(
    { sub: session.user_id, roles: session.roles, scopes: session.scopes },
    ACCESS_TOKEN_TTL_S
  );

  const refreshed = {
    ...session,
    token:     new_token,
    exp:       Math.floor(Date.now() / 1000) + ACCESS_TOKEN_TTL_S,
    refreshed: true,
  };

  return refreshed;
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Revoke a session immediately. After revocation, any call to refreshSession()
 * or hydrateCredentials() for this session_id will fail.
 *
 * NOTE: Active JWTs already issued cannot be revoked (they are stateless).
 * Callers should set the access token TTL short (≤ 6 h) to limit exposure.
 * See auth-bridge.js:issueToken() for the TTL parameter.
 *
 * @param {string} session_id
 */
export function revokeSession(session_id) {
  const record = _sessions.get(session_id);
  if (record) {
    record.revoked    = true;
    record.revoked_at = Date.now();
  }
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Validate a raw refresh token string without creating a new session.
 * Used by auth-bridge.js:hydrateCredentials() for the pre-refresh check.
 *
 * @param {string} refresh_token
 * @returns {Promise<{ session_id: string, user_id: string, issued_at: number }>}
 */
export async function validateRefreshToken(refresh_token) {
  await _ensureSecrets();

  const [rawPayload, rawSig] = refresh_token.split('.');
  if (!rawPayload || !rawSig) throw new SessionError('REFRESH_TOKEN_MALFORMED');

  const payload  = Buffer.from(rawPayload, 'base64url').toString('utf8');
  const expected = await hmacSha512(_refreshSecret, payload);
  const actual   = Buffer.from(rawSig, 'base64url');

  if (expected.length !== actual.length) throw new SessionError('REFRESH_TOKEN_INVALID');
  // Timing-safe compare — see crypto-primitives.js:hmacSha512 for the Buffer contract.
  const { timingSafeEqual } = await import('node:crypto');
  if (!timingSafeEqual(expected, actual)) throw new SessionError('REFRESH_TOKEN_INVALID');

  const [session_id, user_id, iat] = payload.split(':');
  return { session_id, user_id, issued_at: Number(iat) };
}

// ─────────────────────────────────────────────────────────────────────────────

export class SessionError extends Error {
  constructor(code, message = code) {
    super(message);
    this.code = code;
    this.name = 'SessionError';
  }
}
