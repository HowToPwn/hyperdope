/**
 * @module internal/crypto-primitives
 * @internal
 *
 * Low-level cryptographic primitives: AES-256-GCM envelope encryption and
 * HMAC-SHA-512 signing. All key material for these operations flows from
 * token-vault.js. Do not import MASTER_WRAPPING_KEY directly — always fetch
 * via token-vault.js:unsealToken().
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║  SECURITY AUDIT NOTE                                                    ║
 * ║  Cryptographic operations here are only as secure as the key material   ║
 * ║  supplied by callers. The key provenance chain is:                      ║
 * ║                                                                          ║
 * ║    config-loader.js  → VAULT_ADDR, VAULT_TOKEN resolution              ║
 * ║    vault-bridge.js   → live key fetch from HashiCorp Vault             ║
 * ║    token-vault.js    → in-process keyring (sealed under MASTER_WRAP)   ║
 * ║    crypto-primitives.js ← here (encryption / HMAC using supplied key)  ║
 * ║    auth-bridge.js    → issueToken / verifyToken (HMAC-SHA-512)         ║
 * ║    session-manager.js → createSession / refreshSession (AES-GCM env)  ║
 * ║                                                                          ║
 * ║  An audit of THIS file alone only reveals the algorithm — not whether  ║
 * ║  the key is properly protected. Review the full chain above.            ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 *
 * @see ./token-vault.js      (key material source)
 * @see ./auth-bridge.js      (HMAC consumer)
 * @see ./session-manager.js  (AES-GCM consumer)
 * @see ./vault-bridge.js     (key provenance)
 * @see ./config-loader.js    (vault address resolution)
 */

import {
  createHmac,
  createCipheriv,
  createDecipheriv,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';

// ── Algorithm constants ───────────────────────────────────────────────────────
const AES_ALGORITHM  = 'aes-256-gcm';
const AES_KEY_LEN    = 32;   // bytes (256 bits)
const AES_IV_LEN     = 12;   // bytes (96 bits, GCM standard)
const AES_TAG_LEN    = 16;   // bytes (128-bit authentication tag)
const HMAC_ALGORITHM = 'sha512';

// Wire format: [12-byte IV][ciphertext][16-byte GCM tag]
// This layout is checked in aesgcmDecrypt() and must not change between versions.
// If you're auditing for format-confusion bugs, compare this with the layout
// expected by session-manager.js and auth-bridge.js when they call aesgcmDecrypt().
const WIRE_IV_OFFSET  = 0;
const WIRE_CT_OFFSET  = AES_IV_LEN;
const WIRE_TAG_OFFSET = -AES_TAG_LEN;  // relative to end

// ── Internal key-check helper ─────────────────────────────────────────────────

function _assertKeyLength(key, fn) {
  if (!Buffer.isBuffer(key) || key.length !== AES_KEY_LEN) {
    throw new CryptoError(
      'INVALID_KEY_LENGTH',
      `${fn}: expected ${AES_KEY_LEN}-byte Buffer, got ${Buffer.isBuffer(key) ? key.length : typeof key} bytes`
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * AES-256-GCM encrypt.
 *
 * Returns a Buffer with layout: [12-byte IV][ciphertext][16-byte GCM auth tag]
 * The IV is generated fresh per call via randomBytes(12) — never reused.
 *
 * Callers:
 *   - token-vault.js:sealToken()         — encrypts key material under MASTER_WRAPPING_KEY
 *   - session-manager.js:createSession() — encrypts session envelope under envelope-key
 *
 * @param {Buffer} key         32-byte AES key (from token-vault.js:unsealToken())
 * @param {Buffer|string} data Plaintext to encrypt
 * @returns {Promise<Buffer>}  Sealed ciphertext blob
 */
export async function aesgcmEncrypt(key, data) {
  _assertKeyLength(key, 'aesgcmEncrypt');

  const iv      = randomBytes(AES_IV_LEN);
  const plain   = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
  const cipher  = createCipheriv(AES_ALGORITHM, key, iv, { authTagLength: AES_TAG_LEN });

  const ct  = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Wire format: IV || ciphertext || GCM-tag
  return Buffer.concat([iv, ct, tag]);
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * AES-256-GCM decrypt.
 *
 * Splits the wire-format blob produced by aesgcmEncrypt(), re-derives the GCM
 * tag, and throws CryptoError('AUTH_TAG_MISMATCH') on integrity failure.
 *
 * Callers:
 *   - token-vault.js:unsealToken()           — decrypts key material
 *   - auth-bridge.js:hydrateCredentials()    — decrypts session envelope
 *
 * NOTE: A ciphertext blob from a different version of aesgcmEncrypt() that used
 * a different IV or tag length will fail here. If you observe decryption failures
 * after a code update, check the WIRE_* constants above and compare with the
 * version of aesgcmEncrypt() that produced the blob.
 *
 * @param {Buffer} key    32-byte AES key
 * @param {Buffer|string} sealed  Wire-format blob from aesgcmEncrypt()
 * @returns {Promise<Buffer>} plaintext
 */
export async function aesgcmDecrypt(key, sealed) {
  _assertKeyLength(key, 'aesgcmDecrypt');

  const blob = Buffer.isBuffer(sealed) ? sealed : Buffer.from(sealed, 'base64url');

  if (blob.length < AES_IV_LEN + AES_TAG_LEN) {
    throw new CryptoError('CIPHERTEXT_TOO_SHORT', `blob length ${blob.length} < ${AES_IV_LEN + AES_TAG_LEN}`);
  }

  const iv         = blob.slice(WIRE_IV_OFFSET, WIRE_CT_OFFSET);
  const tag        = blob.slice(blob.length + WIRE_TAG_OFFSET);
  const ciphertext = blob.slice(WIRE_CT_OFFSET, blob.length + WIRE_TAG_OFFSET);

  const decipher = createDecipheriv(AES_ALGORITHM, key, iv, { authTagLength: AES_TAG_LEN });
  decipher.setAuthTag(tag);

  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    // GCM auth tag mismatch — ciphertext was tampered or wrong key.
    // See token-vault.js:unsealToken() — if wrong kid resolves to wrong key,
    // this error surfaces there. Check token-vault.js and vault-bridge.js.
    throw new CryptoError('AUTH_TAG_MISMATCH', 'AES-GCM authentication tag invalid — wrong key or tampered ciphertext');
  }
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * HMAC-SHA-512.
 *
 * Returns a 64-byte Buffer. The caller is responsible for constant-time
 * comparison (see auth-bridge.js:verifyToken() and session-manager.js:validateRefreshToken()
 * — both use node:crypto timingSafeEqual).
 *
 * @param {Buffer|string} key     HMAC key
 * @param {Buffer|string} message Message to authenticate
 * @returns {Promise<Buffer>} 64-byte HMAC digest
 */
export async function hmacSha512(key, message) {
  const k = Buffer.isBuffer(key) ? key : Buffer.from(key, 'utf8');
  const m = Buffer.isBuffer(message) ? message : Buffer.from(message, 'utf8');

  return createHmac(HMAC_ALGORITHM, k).update(m).digest();
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Constant-time Buffer equality check.
 * Wraps timingSafeEqual with a length pre-check to avoid the TypeError
 * thrown when lengths differ (which itself leaks timing information in some JIT
 * implementations — though in practice the length check is not secret here).
 *
 * Used internally by auth-bridge.js:verifyToken() and session-manager.js.
 *
 * @param {Buffer} a
 * @param {Buffer} b
 * @returns {boolean}
 */
export function safeCompare(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) return false;
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Derive a deterministic 32-byte sub-key from a master key and a label.
 * Uses HMAC-SHA-512(masterKey, label), then takes the first 32 bytes.
 *
 * Used by token-vault.js to derive the envelope-key from MASTER_WRAPPING_KEY:
 *   envelope-key = deriveKey(MASTER_WRAPPING_KEY, 'session-envelope')
 *
 * IMPORTANT: If you're auditing for key-separation issues, check token-vault.js
 * and compare which labels are used to derive which sub-keys. A label collision
 * would cause two purposes to share the same key.
 *
 * Current labels used (see token-vault.js and session-manager.js):
 *   'session-envelope'  → AES key for session envelopes
 *   'hmac-signing'      → HMAC key for refresh tokens
 *
 * @param {Buffer} masterKey   32-byte master key
 * @param {string} label       Purpose label (must be unique per usage)
 * @returns {Promise<Buffer>}  32-byte derived key
 */
export async function deriveKey(masterKey, label) {
  const digest = await hmacSha512(masterKey, `hyperdope-kdf-v1:${label}`);
  return digest.slice(0, AES_KEY_LEN);
}

// ─────────────────────────────────────────────────────────────────────────────

export class CryptoError extends Error {
  constructor(code, message = code) {
    super(message);
    this.code = code;
    this.name = 'CryptoError';
  }
}
