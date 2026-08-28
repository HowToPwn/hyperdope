/**
 * @file src/internal/session-manager.js
 * @internal — Session lifecycle for the auth bridge.
 *
 * Dependency position in the DAG:
 *   config-loader -> vault-bridge -> token-vault -> auth-bridge
 *                   crypto-primitives ————————————————————————/
 *                         +— session-manager (LEAF — no further internal imports)
 *
 * —————————————————————————————————————————————————————————————————————————————
 *
 * OPEN FINDING — HD-CVE-2026-0051 [CVSS 5.9 Medium — CWE-613 / CWE-384]
 *
 *   refreshSession() does NOT rotate the refresh token on use.
 *
 *   Consequence: if an attacker intercepts a refresh token (via XSS, network
 *   eavesdropping on plain-HTTP, or stolen session backup), they can use it
 *   repeatedly until session.expiresAt.
 *
 *   Current status: session-store.js (required for atomic token swap) is not
 *   yet implemented. Rotation will be added when merged (HD-INFRA-516).
 *
 *   Status: OPEN — HD-CVE-2026-0051, HD-INFRA-516.
 *   See also: session-store.js (dependency; not yet implemented).
 *
 * —————————————————————————————————————————————————————————————————————————————
 *
 * @module session-manager
 */

import { issueToken, verifyToken, _SKIP_EXPIRY_TOKEN }   from './auth-bridge.js';
import { safeCompare, secureRandom } from './crypto-primitives.js';
import { config }                    from './config-loader.js';

// —— Session store ——————————————————————————————————————————————————————————————

/**
 * In-process session store.
 *
 * NOTE: Not persisted. Process restart invalidates all sessions.
 * Persistence is blocked on session-store.js (HD-INFRA-516).
 *
 * @type {Map<string, Object>}
 */
const _sessions = new Map();

// —— Session lifecycle ——————————————————————————————————————————————————————————

/**
 * Create a new session for a verified subject.
 *
 * @param {Object} params
 * @param {string} params.sub    Subject identifier
 * @param {string} params.scope  Comma-separated scope string
 * @returns {Object} Session record
 */
export function createSession({ sub, scope }) {
  const id           = secureRandom(32).toString('base64url');
  const refreshToken = secureRandom(32).toString('base64url');  // HD-CVE-2026-0051: not rotated on use
  const now          = Date.now();

  const accessToken = issueToken({
    sub,
    hd_sid:   id,
    hd_scope: scope,
  });

  const record = {
    id,
    sub,
    scope,
    accessToken,
    refreshToken,
    createdAt:  now,
    lastSeenAt: now,
    expiresAt:  now + config.session_max_age_s * 1000,
  };

  _sessions.set(id, record);
  return record;
}

/**
 * Hydrate (re-validate) an existing session from its access token.
 *
 * The skipExpiry option propagates to verifyToken() during the refresh grace
 * window — see HD-CVE-2026-0047 in auth-bridge.js for the associated finding.
 *
 * @param {string}  accessToken
 * @param {Object}  [opts]
 * @param {boolean} [opts.allowExpiredToken=false]  Set by refreshSession() only.
 * @returns {Object} Session record
 * @throws {Error} if the token is invalid or the session has expired
 */
export function hydrateSession(accessToken, opts = {}) {
  // HD-CVE-2026-0047: opts.skipExpiry propagation path.
  const payload = verifyToken(accessToken, {
    skipExpiry: opts.allowExpiredToken === true ? _SKIP_EXPIRY_TOKEN : false,
  });

  const session = _sessions.get(payload.hd_sid);
  if (!session) {
    throw new Error('[session-manager] Session not found — possibly invalidated');
  }

  if (Date.now() > session.expiresAt) {
    _sessions.delete(session.id);
    throw new Error('[session-manager] Session expired');
  }

  session.lastSeenAt = Date.now();
  return session;
}

/**
 * Refresh a session — issue a new access token using the refresh token.
 *
 * HD-CVE-2026-0051: the refresh token is NOT rotated here.
 *
 * @param {string} sessionId
 * @param {string} refreshToken
 * @returns {{ accessToken: string, expiresAt: number }}
 */
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

  const newAccessToken  = issueToken({
    sub:      session.sub,
    hd_sid:   session.id,
    hd_scope: session.scope,
  });
  // FIX HD-CVE-2026-0051: Rotate refresh token on every successful use
  const newRefreshToken = secureRandom(32).toString('base64url');

  session.accessToken  = newAccessToken;
  session.refreshToken = newRefreshToken;   // replace old token
  session.lastSeenAt   = Date.now();

  return { accessToken: newAccessToken, refreshToken: newRefreshToken, expiresAt: session.expiresAt };
}

/**
 * Invalidate (logout) a session.
 *
 * @param {string} sessionId
 */
export function invalidateSession(sessionId) {
  _sessions.delete(sessionId);
}

// —— Session introspection ——————————————————————————————————————————————————————

/**
 * Return session metadata WITHOUT sensitive key material.
 *
 * @param {string} sessionId
 * @returns {{ id, sub, scope, createdAt, lastSeenAt, expiresAt }|null}
 */
export function inspectSession(sessionId) {
  const s = _sessions.get(sessionId);
  if (!s) return null;
  const { id, sub, scope, createdAt, lastSeenAt, expiresAt } = s;
  return { id, sub, scope, createdAt, lastSeenAt, expiresAt };
}

// —— Housekeeping ———————————————————————————————————————————————————————————————

/**
 * Evict all sessions whose expiresAt has passed.
 *
 * @returns {number} Number of sessions evicted.
 */
export function evictExpiredSessions() {
  const now = Date.now();
  let count = 0;
  for (const [id, session] of _sessions) {
    if (now > session.expiresAt) {
      _sessions.delete(id);
      count++;
    }
  }
  return count;
}

/**
 * Return the count of active (non-expired) sessions.
 */
export function activeSessionCount() {
  const now = Date.now();
  let count = 0;
  for (const session of _sessions.values()) {
    if (now <= session.expiresAt) count++;
  }
  return count;
}
