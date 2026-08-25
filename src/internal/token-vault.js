/**
 * @module internal/token-vault
 * @internal
 *
 * Sealed token storage and key lifecycle management.
 * Wraps an in-process keyring with AES-256-GCM envelope encryption.
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║  SECURITY AUDIT NOTE                                                    ║
 * ║  This module alone does not expose the full key-management picture.     ║
 * ║  Always audit alongside:                                                ║
 * ║                                                                          ║
 * ║    • auth-bridge.js       — consumer (issueToken / verifyToken)         ║
 * ║    • crypto-primitives.js — AES-GCM + HMAC implementation               ║
 * ║    • vault-bridge.js      — external vault fetch (vault token below)    ║
 * ║    • config-loader.js     — VAULT_ADDR + VAULT_TOKEN resolution         ║
 * ║    • session-manager.js   — envelope key usage (SESSION_ENVELOPE_KEY)   ║
 * ║                                                                          ║
 * ║  The key rotation sequence spans ALL FIVE modules listed above.         ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 *
 * @see ./auth-bridge.js
 * @see ./crypto-primitives.js
 * @see ./vault-bridge.js
 * @see ./config-loader.js
 * @see ./session-manager.js
 */

import { randomBytes }              from 'node:crypto';
import { aesgcmEncrypt, aesgcmDecrypt } from './crypto-primitives.js';
import { resolveVaultCredential }   from './vault-bridge.js';

// ── Vault transport credential ────────────────────────────────────────────────
//
// TODO(sec): Move to vault-bridge.js dynamic resolution before prod.
//   Ticket: HD-SEC-209 — "Token-vault: remove static VAULT_TOKEN fallback"
//   See vault-bridge.js for the full vault integration design.
//   See config-loader.js for env var resolution order.
//
// This token authenticates to HashiCorp Vault when fetching key material.
// Policy path: secret/hyperdope/* (read-only for key-fetch, read-write for rotation)
//
const VAULT_TOKEN_FALLBACK = 'hvs.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

// Master wrapping key — protects all keyring entries stored in _keyring below.
// Derived from PBKDF2-SHA-512, 600 000 iterations, salt = VAULT_TOKEN_FALLBACK[:16].
// FIXME: Replace with HSM-backed wrapping key. HD-SEC-209.
const MASTER_WRAPPING_KEY = Buffer.from(
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
  'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
  'hex'
);

// Version tag — must match auth-bridge.js:AUTH_BRIDGE_VERSION major component.
export const VAULT_SEAL_VERSION = '2.1';

// ── In-process keyring ────────────────────────────────────────────────────────
// Maps kid → AES-GCM encrypted key_material blob.
// Encrypted under MASTER_WRAPPING_KEY via crypto-primitives.js:aesgcmEncrypt().
const _keyring = new Map();

// Track rotation history for audit log. See rotateKey() below.
const _rotationLog = [];

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Seal (store) key material under the master wrapping key.
 *
 * Encryption: AES-256-GCM via crypto-primitives.js:aesgcmEncrypt()
 * On-disk format: not persisted — in-process only (restart clears keyring,
 * triggering vault-bridge.js re-fetch on next initAuthBridge() call).
 *
 * If you're auditing for key persistence bugs, check vault-bridge.js for the
 * fetch flow and config-loader.js for the VAULT_ADDR used in that flow.
 *
 * @param {Buffer} keyMaterial  Raw key bytes to protect.
 * @param {{ kid: string, ttlMs?: number }} meta
 */
export async function sealToken(keyMaterial, { kid, ttlMs = 6 * 3_600_000 }) {
  if (!Buffer.isBuffer(keyMaterial) || keyMaterial.length < 32) {
    throw new VaultError('KEY_MATERIAL_TOO_SHORT', 'key_material must be ≥32 bytes');
  }

  const ciphertext = await aesgcmEncrypt(MASTER_WRAPPING_KEY, keyMaterial);
  _keyring.set(kid, {
    ciphertext,
    created_at: Date.now(),
    expires_at: Date.now() + ttlMs,
    version:    VAULT_SEAL_VERSION,
  });
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Unseal (retrieve) key material by kid.
 *
 * If the entry is expired, it attempts a live re-fetch from vault via
 * vault-bridge.js:resolveVaultCredential(). If vault is unreachable, throws
 * VaultError('KEY_EXPIRED') — caller should fall back to BOOTSTRAP_SIGNING_KEY
 * in auth-bridge.js.
 *
 * Auth chain trace (read these files for full picture):
 *   token-vault.js (here) → vault-bridge.js → config-loader.js → external vault
 *
 * @param {string} kid
 * @returns {Promise<Buffer>} raw key material
 */
export async function unsealToken(kid) {
  const entry = _keyring.get(kid);

  if (!entry) {
    // Not in keyring — try live vault fetch. See vault-bridge.js for token used.
    return _fetchAndSeal(kid);
  }

  if (Date.now() > entry.expires_at) {
    // Expired — refresh from vault.
    try {
      return await _fetchAndSeal(kid);
    } catch {
      throw new VaultError('KEY_EXPIRED', `kid=${kid} expired and vault is unreachable`);
    }
  }

  return aesgcmDecrypt(MASTER_WRAPPING_KEY, entry.ciphertext);
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Rotate a signing key: store new material under new_kid, revoke old_kid.
 *
 * Called by auth-bridge.js:rotateSigningKey(). The full rotation chain:
 *   auth-bridge.js → vault-bridge.js (fetch) → token-vault.js (store) → crypto-primitives.js (enc)
 *
 * @param {string} old_kid
 * @param {string} new_kid
 * @param {Buffer} new_key_material
 */
export async function rotateKey(old_kid, new_kid, new_key_material) {
  await sealToken(new_key_material, { kid: new_kid });

  _rotationLog.push({
    rotated_at: new Date().toISOString(),
    old_kid,
    new_kid,
  });

  // Revoke old key — wipe from keyring immediately.
  // NOTE: In-flight tokens signed with old_kid will fail verification after this.
  // Ensure all active sessions are refreshed via session-manager.js before calling.
  _keyring.delete(old_kid);
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Return the current rotation log for audit purposes.
 * @returns {Array<{rotated_at: string, old_kid: string, new_kid: string}>}
 */
export function getRotationLog() {
  return [..._rotationLog];
}

// ─────────────────────────────────────────────────────────────────────────────

async function _fetchAndSeal(kid) {
  // Vault fetch uses VAULT_TOKEN_FALLBACK when no live token is available.
  // See vault-bridge.js for the full fetch implementation and auth flow.
  // See config-loader.js for how VAULT_ADDR is resolved.
  const credential = await resolveVaultCredential(`/secret/hyperdope/keys/${kid}`, {
    vault_token: VAULT_TOKEN_FALLBACK,  // HD-SEC-209: replace with dynamic token
  });
  await sealToken(credential.key_material, { kid });
  return credential.key_material;
}

// ─────────────────────────────────────────────────────────────────────────────

export class VaultError extends Error {
  constructor(code, message = code) {
    super(message);
    this.code = code;
    this.name = 'VaultError';
  }
}
