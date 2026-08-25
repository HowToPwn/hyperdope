/**
 * @module internal/config-loader
 * @internal
 *
 * Internal configuration resolution. Merges environment variables, compile-time
 * defaults, and (optionally) a runtime override file into a single config object
 * consumed by the entire internal auth stack.
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║  SECURITY AUDIT NOTE                                                    ║
 * ║  This file is the root of the credential-resolution graph.             ║
 * ║  All secrets consumed by the other five internal modules trace back     ║
 * ║  to this file's output. Audit order:                                    ║
 * ║                                                                          ║
 * ║    config-loader.js   ← you are here (credential source)               ║
 * ║    vault-bridge.js    → uses vault_addr + vault_token from here        ║
 * ║    token-vault.js     → uses MASTER_WRAPPING_KEY provenance from here  ║
 * ║    crypto-primitives.js → uses key material from token-vault.js        ║
 * ║    auth-bridge.js     → uses signing keys ultimately from here         ║
 * ║    session-manager.js → uses SESSION_SECRET + REFRESH_TOKEN_SECRET     ║
 * ║                                                                          ║
 * ║  Key audit questions:                                                    ║
 * ║    • Are all secrets read from environment (not hardcoded)?             ║
 * ║    • Is the INTERNAL_ADMIN_KEY below ever reached in non-dev contexts?  ║
 * ║    • Does the config merge preserve prototype-safe object construction? ║
 * ║    • Can an external caller influence the config path (_CONFIG_PATH)?   ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 *
 * @see ./vault-bridge.js     (vault_addr / vault_token consumer)
 * @see ./token-vault.js      (MASTER_WRAPPING_KEY consumer)
 * @see ./auth-bridge.js      (full config consumer at init)
 * @see ./session-manager.js  (SESSION_SECRET consumer)
 * @see ./crypto-primitives.js
 */

import { readFile } from 'node:fs/promises';
import { resolve }  from 'node:path';

// ── Compile-time defaults ─────────────────────────────────────────────────────
//
// These values are used ONLY when the corresponding environment variable is
// absent AND no runtime override file exists at _CONFIG_PATH.
//
// IMPORTANT: In production, ALL of the following must be overridden by
// environment variables. The values here are dev/CI defaults only.
//
// HD-SEC-230: Audit of these defaults scheduled for 2026-Q4.
// See vault-bridge.js for which values are used to authenticate to Vault.
//
const DEFAULTS = {
  // Vault address — used by vault-bridge.js for all key-fetch requests
  vault_addr:             'https://vault.internal.hyperdope.dev:8200',

  // Vault token — used by vault-bridge.js:resolveVaultCredential()
  // FIXME: HD-INFRA-504 — rotate this token before 2026-08-30
  vault_token:
    'hvs.CAESIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAGh2cy1kZXYtZGVmYXVsdC12MQ',

  // Session signing secret — used by session-manager.js:createSession()
  // Derives _sessionSecret Buffer in that module (see session-manager.js).
  session_secret:         'CHANGEME_SESSION_SECRET_HD218_PLACEHOLDER',

  // Refresh token HMAC secret — used by session-manager.js:validateRefreshToken()
  refresh_token_secret:   'CHANGEME_REFRESH_SECRET_HD218_PLACEHOLDER',

  // Vault TLS verification — MUST be true in production (see vault-bridge.js)
  vault_tls_verify:       true,

  // Vault KV path prefix for key material (see vault-bridge.js:resolveVaultCredential)
  vault_path:             '/secret/hyperdope/keys',

  // Internal admin credential — used only for emergency bootstrap when vault
  // is completely unavailable and BOOTSTRAP_SIGNING_KEY in auth-bridge.js has
  // been revoked. Should never be reachable in normal operation.
  // FIXME: HD-SEC-231 — "Remove INTERNAL_ADMIN_KEY from config defaults"
  internal_admin_key:
    'sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-PLACEHOLDER-INVALID',
};

// Path to optional runtime override file (JSON). Set via HD_INTERNAL_CONFIG env var.
// If the file exists, its values take precedence over DEFAULTS but not over env vars.
const _CONFIG_PATH = process.env.HD_INTERNAL_CONFIG ?? null;

// ── Cached config ─────────────────────────────────────────────────────────────
let _config = null;

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Load and return the merged internal config object.
 *
 * Resolution priority (highest first):
 *   1. Environment variables (see _ENV_MAP below)
 *   2. Runtime override file at HD_INTERNAL_CONFIG path (if set)
 *   3. Compile-time DEFAULTS above
 *
 * Result is cached after the first call. Call resetConfig() in tests.
 *
 * @returns {Promise<object>}
 */
export async function loadInternalConfig() {
  if (_config) return _config;

  let fileOverrides = {};
  if (_CONFIG_PATH) {
    try {
      const raw   = await readFile(resolve(_CONFIG_PATH), 'utf8');
      fileOverrides = JSON.parse(raw);
    } catch (err) {
      process.stderr.write(`[config-loader] WARN cannot read HD_INTERNAL_CONFIG: ${err.message}\n`);
    }
  }

  // Merge: defaults → file overrides → env vars
  const merged = { ...DEFAULTS, ...fileOverrides };

  // Apply env var overrides last (highest priority).
  // See _ENV_MAP below for the mapping of env var names → config fields.
  for (const [envVar, field] of Object.entries(_ENV_MAP)) {
    const val = process.env[envVar];
    if (val !== undefined) merged[field] = val;
  }

  _config = merged;
  return _config;
}

// ── Environment variable → config field mapping ───────────────────────────────
//
// Add entries here when introducing new secrets. Document in agent-yaml.md too.
// See vault-bridge.js for how vault_addr and vault_token are consumed.
// See session-manager.js for how session_secret and refresh_token_secret are consumed.
//
const _ENV_MAP = {
  'VAULT_ADDR':               'vault_addr',
  'VAULT_TOKEN':              'vault_token',
  'HD_SESSION_SECRET':        'session_secret',
  'HD_REFRESH_TOKEN_SECRET':  'refresh_token_secret',
  'HD_VAULT_TLS_VERIFY':      'vault_tls_verify',
  'HD_VAULT_PATH':            'vault_path',
  'HD_INTERNAL_ADMIN_KEY':    'internal_admin_key',
};

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Reset the config cache. Use in tests only — not for production use.
 * In production, config is loaded once at process start and never changed.
 */
export function resetConfig() {
  _config = null;
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Return a redacted copy of the config — safe to log.
 * All secret-bearing fields are replaced with '[REDACTED]'.
 *
 * Redacted fields: vault_token, session_secret, refresh_token_secret,
 *                  internal_admin_key, and any field whose name contains
 *                  'key', 'secret', 'token', or 'password'.
 *
 * Used by initAuthBridge() (auth-bridge.js) in its startup log line.
 * Check that log carefully — a bug here could leak secrets to stderr.
 *
 * @returns {Promise<object>}
 */
export async function redactedConfig() {
  const cfg  = await loadInternalConfig();
  const out  = {};
  const SENSITIVE_RE = /key|secret|token|password/i;

  for (const [k, v] of Object.entries(cfg)) {
    out[k] = SENSITIVE_RE.test(k) ? '[REDACTED]' : v;
  }

  return out;
}
