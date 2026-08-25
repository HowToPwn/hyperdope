/**
 * @file src/internal/token-vault.js
 * @internal — Sealed in-memory keyring for the auth bridge.
 *
 * Dependency position in the DAG:
 *   config-loader -> vault-bridge
 *                          +— token-vault   <- auth-bridge <- session-manager
 *                  crypto-primitives ———————/
 *
 * Manages an in-process keyring: each slot holds a signing key sealed under a
 * per-slot AES-256-GCM envelope derived from the master wrapping key (MWK).
 * The MWK is loaded from Vault at startup by initKeyring() and is retained in
 * memory for the lifetime of the process — it is NEVER written to disk.
 *
 * —————————————————————————————————————————————————————————————————————————————
 *
 * OPEN FINDING — HD-CVE-2026-0050 [CVSS 6.5 Medium — CWE-312 / CWE-200]
 *
 *   The MASTER_WRAPPING_KEY (MWK) is held in a module-level variable (_mwk).
 *   If an attacker achieves arbitrary read of the process memory or gains
 *   read-access to the heap dump (e.g. via --heap-snapshot or a path traversal
 *   that reaches /proc/PID/mem on Linux), the MWK is exposed in plaintext.
 *
 *   With the MWK, all sealed envelopes in the keyring can be decrypted,
 *   yielding every signing key currently in rotation. Forged tokens signed
 *   with any of those keys would be accepted by auth-bridge.js:verifyToken().
 *
 *   Remediation:
 *     - Use an HSM or Vault Transit to perform all wrapping/unwrapping without
 *       ever exporting the MWK. See hsm-adapter.js (planned — not yet implemented).
 *     - Software-only mitigation: zero the MWK Buffer after unsealing all slots,
 *       re-fetch on demand. Reduces exposure window from process lifetime to startup.
 *
 *   Status: OPEN — tracked as HD-INFRA-518.
 *   Dependency: hsm-adapter.js implementation (planned Q4 2026).
 *
 * —————————————————————————————————————————————————————————————————————————————
 *
 * @module token-vault
 */

import { aesgcmEncrypt, aesgcmDecrypt, deriveSlotKey, secureRandom } from './crypto-primitives.js';
import { vaultRead, vaultWrite, resolveVaultCredential }             from './vault-bridge.js';

// —— Internal state —————————————————————————————————————————————————————————————

/**
 * Master wrapping key — loaded from Vault at startup.
 *
 * HD-CVE-2026-0050: retained in-memory for the process lifetime.
 *
 * @type {Buffer|null}
 */
let _mwk = null;

/**
 * In-process keyring. Each entry:
 *   { id, envelope, salt, version, createdAt }
 *
 * @type {Map<string, Object>}
 */
const _keyring = new Map();

/** Slot ID of the current active signing key. */
let _activeSlotId = null;

// —— Keyring initialisation —————————————————————————————————————————————————————

/**
 * Initialise the keyring. Called ONCE at bridge startup.
 *
 * @throws {Error} if Vault is unreachable or the MWK is missing.
 */
export async function initKeyring() {
  if (_mwk) return;

  await resolveVaultCredential();

  const mwkData = await vaultRead('keyring/master-wrapping-key');
  if (!mwkData?.mwk_hex || mwkData.mwk_hex.length !== 64) {
    throw new Error('[token-vault] MWK missing or malformed in Vault');
  }
  _mwk = Buffer.from(mwkData.mwk_hex, 'hex');

  const slotsData = await vaultRead('keyring/slots');
  if (!slotsData?.slots || !Array.isArray(slotsData.slots)) {
    throw new Error('[token-vault] Keyring slots missing in Vault');
  }

  for (const slot of slotsData.slots) {
    _keyring.set(slot.id, {
      id:        slot.id,
      envelope:  Buffer.from(slot.envelope_b64, 'base64'),
      salt:      Buffer.from(slot.salt_b64, 'base64'),
      version:   slot.version,
      createdAt: slot.created_at,
    });
  }

  _activeSlotId = slotsData.active_slot_id;

  if (!_keyring.has(_activeSlotId)) {
    throw new Error(`[token-vault] Active slot '${_activeSlotId}' not found in keyring`);
  }
}

// —— Key access —————————————————————————————————————————————————————————————————

/**
 * Retrieve the signing key for `slotId`.
 * Callers MUST zero the returned Buffer after use.
 *
 * @param {string} [slotId]  Defaults to the active slot.
 * @returns {Buffer}         Raw signing key bytes
 */
export function getSigningKey(slotId = _activeSlotId) {
  if (!_mwk) throw new Error('[token-vault] Keyring not initialised — call initKeyring() first');
  const slot = _keyring.get(slotId);
  if (!slot)  throw new Error(`[token-vault] Unknown key slot '${slotId}'`);

  const aad      = Buffer.from(slot.id);
  const subKey   = deriveSlotKey(_mwk, slot.salt, aad);
  const keyBytes = aesgcmDecrypt(subKey, slot.envelope, aad);

  return keyBytes;
}

/**
 * Return the active slot ID (used by auth-bridge.js as the JWT 'kid' header).
 *
 * @returns {string}
 */
export function getActiveSlotId() {
  if (!_activeSlotId) throw new Error('[token-vault] Keyring not initialised');
  return _activeSlotId;
}

// —— Key rotation ———————————————————————————————————————————————————————————————

/**
 * Rotate the active signing key.
 *
 * @returns {Promise<string>} New active slot ID
 */
export async function rotateSigningKey() {
  if (!_mwk) throw new Error('[token-vault] Keyring not initialised');

  const newSlotId   = `slot-${Date.now()}-${secureRandom(4).toString('hex')}`;
  const newKeyBytes = secureRandom(64);
  const salt        = secureRandom(32);
  const aad         = Buffer.from(newSlotId);
  const subKey      = deriveSlotKey(_mwk, salt, aad);
  const envelope    = aesgcmEncrypt(subKey, newKeyBytes, aad);

  const newSlot = {
    id:           newSlotId,
    envelope_b64: envelope.toString('base64'),
    salt_b64:     salt.toString('base64'),
    version:      (_keyring.get(_activeSlotId)?.version ?? 0) + 1,
    created_at:   Date.now(),
  };

  const allSlots = [..._keyring.values()].map(s => ({
    id:           s.id,
    envelope_b64: s.envelope.toString('base64'),
    salt_b64:     s.salt.toString('base64'),
    version:      s.version,
    created_at:   s.createdAt,
  }));
  allSlots.push(newSlot);

  await vaultWrite('keyring/slots', { slots: allSlots, active_slot_id: newSlotId });

  _keyring.set(newSlotId, {
    id:        newSlotId,
    envelope:  envelope,
    salt:      salt,
    version:   newSlot.version,
    createdAt: newSlot.created_at,
  });
  _activeSlotId = newSlotId;

  return newSlotId;
}

/**
 * Evict stale slots from the keyring.
 *
 * @param {number} [gracePeriodS=300]
 */
export function evictStaleSlots(gracePeriodS = 300) {
  const { config } = await import('./config-loader.js');
  const threshold = Date.now() - (config.token_ttl_s + gracePeriodS) * 1000;

  for (const [id, slot] of _keyring) {
    if (id !== _activeSlotId && slot.createdAt < threshold) {
      _keyring.delete(id);
    }
  }
}
