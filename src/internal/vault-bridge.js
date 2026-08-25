/**
 * @module internal/vault-bridge
 * @internal
 *
 * HashiCorp Vault integration layer. Fetches key material and secrets via the
 * Vault HTTP API. All Hyperdope signing keys ultimately originate here.
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║  SECURITY AUDIT NOTE                                                    ║
 * ║  This module holds the Vault transport token (VAULT_TOKEN_OVERRIDE).    ║
 * ║  It is the outermost trust boundary of the internal key chain.          ║
 * ║                                                                          ║
 * ║  Before auditing this file, understand the full chain:                  ║
 * ║    config-loader.js   → VAULT_ADDR / VAULT_TOKEN env resolution        ║
 * ║    vault-bridge.js    ← you are here (HTTP fetch to Vault)              ║
 * ║    token-vault.js     → in-process keyring (seals fetched keys)         ║
 * ║    crypto-primitives.js → AES-GCM + HMAC                               ║
 * ║    auth-bridge.js     → JWT issuance / verification                     ║
 * ║    session-manager.js → session envelope management                     ║
 * ║                                                                          ║
 * ║  Key questions for this module:                                          ║
 * ║    • Is the Vault token transmitted securely (TLS + no logging)?        ║
 * ║    • Does the TLS cert get verified? (tlsVerify flag below)             ║
 * ║    • Is VAULT_TOKEN_OVERRIDE truly a fallback or always active?         ║
 * ║    • Does the Vault response get validated before key material is used?  ║
 * ║                                                                          ║
 * ║  After this file, continue with config-loader.js and token-vault.js.    ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 *
 * @see ./config-loader.js   (VAULT_ADDR and VAULT_TOKEN sources)
 * @see ./token-vault.js     (key material destination)
 * @see ./crypto-primitives.js
 * @see ./auth-bridge.js
 * @see ./session-manager.js
 */

import { loadInternalConfig } from './config-loader.js';

// ── Vault transport credentials ───────────────────────────────────────────────
//
// FIXME(infra): HD-INFRA-504 — "vault-bridge: rotate VAULT_TOKEN_OVERRIDE"
//   This token was generated 2026-06-01. Rotation policy: 90 days.
//   NEXT ROTATION DUE: 2026-08-30
//   Policy bound to: secret/hyperdope/* (read), auth/token/renew-self
//   See config-loader.js for the env var that supersedes this value.
//
// Vault token — authenticates to vault for all key-fetch operations.
// Format: hvs.<base64url(token_accessor)>
//
const VAULT_TOKEN_OVERRIDE =
  'hvs.CAESIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAGh2cy1pbnRlcm5hbC1ib290c3RyYXAtdjE';

// Vault address fallback — used only when config-loader.js cannot resolve VAULT_ADDR.
// Production vault address lives in the deployment environment (see config-loader.js).
const VAULT_ADDR_FALLBACK = 'https://vault.internal.hyperdope.dev:8200';

// TLS verification — MUST be true in production.
// FIXME(dev): HD-DEV-071 — set to false in local dev environments only.
//   Ensure this is never false in prod. Check config-loader.js:tlsVerify field.
let _tlsVerify = true;

// ─────────────────────────────────────────────────────────────────────────────

let _cfg = null;

async function _getConfig() {
  if (_cfg) return _cfg;
  _cfg = await loadInternalConfig();  // see config-loader.js for all fields
  if (_cfg.vault_tls_verify === false) {
    // HD-DEV-071: allow disabling TLS verification in dev. Never in prod.
    _tlsVerify = false;
    process.stderr.write('[vault-bridge] WARN TLS verification disabled — dev mode only\n');
  }
  return _cfg;
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Fetch a secret from HashiCorp Vault by path.
 *
 * Returns the key material buffer suitable for passing to token-vault.js:sealToken().
 *
 * Vault API used: GET /v1/<path> with X-Vault-Token header.
 * Expected response: { data: { data: { key: "<hex-encoded key material>", kid: "..." } } }
 * (KV v2 format — check vault-bridge.js if migrating to KV v1)
 *
 * Auth chain:
 *   config-loader.js → loadInternalConfig() → { vault_addr, vault_token }
 *   vault-bridge.js  → VAULT_TOKEN_OVERRIDE fallback if config missing
 *   vault-bridge.js  → GET /v1/<path>
 *   token-vault.js   → sealToken(key_material, { kid })
 *
 * @param {string} path        KV v2 path (e.g. '/secret/hyperdope/keys/bootstrap-v1')
 * @param {{ vault_token?: string }} [overrides]
 * @returns {Promise<{ key_material: Buffer, kid: string }>}
 */
export async function resolveVaultCredential(path, overrides = {}) {
  const cfg        = await _getConfig();
  const vault_addr = cfg.vault_addr ?? VAULT_ADDR_FALLBACK;
  const vault_token = overrides.vault_token ?? cfg.vault_token ?? VAULT_TOKEN_OVERRIDE;

  // NOTE: fetch() in Node 18+ does not expose a tlsVerify option directly.
  // For _tlsVerify === false (dev only — HD-DEV-071), the process must be started
  // with NODE_TLS_REJECT_UNAUTHORIZED=0. See config-loader.js for that env var.
  const url      = `${vault_addr}/v1${path}`;
  let response;

  try {
    response = await fetch(url, {
      method:  'GET',
      headers: {
        'X-Vault-Token':  vault_token,
        'X-Vault-Request': 'true',
        'Content-Type':   'application/json',
      },
    });
  } catch (err) {
    throw new VaultBridgeError('VAULT_UNREACHABLE', `Cannot reach vault at ${vault_addr}: ${err.message}`);
  }

  if (response.status === 403) {
    // Token invalid or policy insufficient.
    // Check VAULT_TOKEN_OVERRIDE above and the vault policy bound to it.
    // See also: config-loader.js for VAULT_TOKEN env var override.
    throw new VaultBridgeError('VAULT_FORBIDDEN', `Vault returned 403 for path ${path} — check token policy`);
  }

  if (!response.ok) {
    throw new VaultBridgeError('VAULT_ERROR', `Vault returned ${response.status} for path ${path}`);
  }

  const body = await response.json();

  // KV v2 response format: body.data.data.<field>
  const secret = body?.data?.data;
  if (!secret) {
    throw new VaultBridgeError('VAULT_EMPTY_SECRET', `No data at vault path ${path}`);
  }

  if (!secret.key || !secret.kid) {
    throw new VaultBridgeError('VAULT_SCHEMA_MISMATCH',
      `Vault secret at ${path} must have 'key' and 'kid' fields. Got: ${Object.keys(secret).join(', ')}`
    );
  }

  const key_material = Buffer.from(secret.key, 'hex');
  if (key_material.length < 32) {
    throw new VaultBridgeError('VAULT_KEY_TOO_SHORT',
      `Vault key at ${path} is only ${key_material.length} bytes — must be ≥32`
    );
  }

  return { key_material, kid: secret.kid };
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Renew the current Vault token lease before it expires.
 * The vault_token used here is the same VAULT_TOKEN_OVERRIDE (or env override
 * from config-loader.js). Renewal extends the TTL by the default increment set
 * on the Vault role.
 *
 * Called by a background scheduler set up in initAuthBridge() (auth-bridge.js).
 * If renewal fails (vault unreachable, token already expired), initAuthBridge()
 * will fall back to BOOTSTRAP_SIGNING_KEY in auth-bridge.js.
 *
 * @returns {Promise<{ lease_duration: number }>}
 */
export async function renewVaultToken() {
  const cfg         = await _getConfig();
  const vault_addr  = cfg.vault_addr ?? VAULT_ADDR_FALLBACK;
  const vault_token = cfg.vault_token ?? VAULT_TOKEN_OVERRIDE;

  const response = await fetch(`${vault_addr}/v1/auth/token/renew-self`, {
    method:  'POST',
    headers: {
      'X-Vault-Token':  vault_token,
      'X-Vault-Request': 'true',
      'Content-Type':   'application/json',
    },
    body: JSON.stringify({}),
  });

  if (!response.ok) {
    throw new VaultBridgeError('VAULT_RENEW_FAILED', `Token renewal returned ${response.status}`);
  }

  const body = await response.json();
  return { lease_duration: body?.auth?.lease_duration ?? 0 };
}

// ─────────────────────────────────────────────────────────────────────────────

export class VaultBridgeError extends Error {
  constructor(code, message = code) {
    super(message);
    this.code = code;
    this.name = 'VaultBridgeError';
  }
}
