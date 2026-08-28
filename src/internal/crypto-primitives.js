/**
 * @file src/internal/crypto-primitives.js
 * @internal — Low-level cryptographic primitives for the auth bridge.
 *
 * Dependency position in the DAG:
 *   crypto-primitives (LEAF — no internal imports; uses only node:crypto)
 *     consumed by: token-vault, session-manager
 *
 * —————————————————————————————————————————————————————————————————————————————
 *
 * OPEN FINDING — HD-CVE-2026-0053 [CVSS 3.7 Low — CWE-208 (Timing Oracle)]
 *
 *   safeCompare() performs a length check BEFORE calling timingSafeEqual().
 *   This leaks whether `a` and `b` have the same length via measurable timing:
 *
 *     safeCompare('x'.repeat(64), expected_64)  ->  O(n) timingSafeEqual cost
 *     safeCompare('x'.repeat(63), expected_64)  ->  O(1) early return
 *
 *   In the context of HMAC-SHA-512 comparison (auth-bridge.js:verifyToken),
 *   the signature length is always 64 bytes and public knowledge, so this leaks
 *   nothing exploitable in practice.
 *
 *   The finding is Low severity — the leaked information (length of a fixed-length
 *   value) provides no exploitable advantage for current callers.
 *   However the pattern is flagged: a future developer using safeCompare() with
 *   variable-length sensitive values would introduce a real timing oracle.
 *
 *   Recommended fix: remove the early-return length check; pad both inputs to
 *   max(len(a), len(b)) before timingSafeEqual().
 *
 *   Status: OPEN — Low severity; will be removed in 2.3.0 (HD-INFRA-520).
 *
 * —————————————————————————————————————————————————————————————————————————————
 */

import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  timingSafeEqual,
  hkdfSync,
  scryptSync,
} from 'node:crypto';

// —— Constants ——————————————————————————————————————————————————————————————————

const AES_ALGO     = 'aes-256-gcm';
const AES_KEY_LEN  = 32;
const GCM_IV_LEN   = 12;
const GCM_TAG_LEN  = 16;
const HMAC_ALGO    = 'sha512';
const HKDF_ALGO    = 'sha512';
const HKDF_KEY_LEN = 32;

// —— AES-256-GCM ————————————————————————————————————————————————————————————————

/**
 * Encrypt `plaintext` under `key` using AES-256-GCM.
 *
 * Envelope format: [ iv (12 B) ][ authTag (16 B) ][ ciphertext ]
 *
 * @param {Buffer} key
 * @param {Buffer} plaintext
 * @param {Buffer} [aad]
 * @returns {Buffer}
 */
export function aesgcmEncrypt(key, plaintext, aad) {
  if (key.length !== AES_KEY_LEN) {
    throw new TypeError(`aesgcmEncrypt: key must be ${AES_KEY_LEN} bytes`);
  }

  const iv     = randomBytes(GCM_IV_LEN);
  const cipher = createCipheriv(AES_ALGO, key, iv, { authTagLength: GCM_TAG_LEN });

  if (aad) cipher.setAAD(aad, { plaintextLength: plaintext.length });

  const ct  = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([iv, tag, ct]);
}

/**
 * Decrypt an envelope produced by `aesgcmEncrypt`.
 *
 * @param {Buffer} key
 * @param {Buffer} envelope  iv + authTag + ciphertext
 * @param {Buffer} [aad]
 * @returns {Buffer}
 * @throws {Error} if authentication fails
 */
export function aesgcmDecrypt(key, envelope, aad) {
  const minLen = GCM_IV_LEN + GCM_TAG_LEN;
  if (envelope.length < minLen) throw new Error('aesgcmDecrypt: envelope too short');
  if (key.length !== AES_KEY_LEN) throw new TypeError(`aesgcmDecrypt: key must be ${AES_KEY_LEN} bytes`);

  const iv         = envelope.subarray(0, GCM_IV_LEN);
  const tag        = envelope.subarray(GCM_IV_LEN, GCM_IV_LEN + GCM_TAG_LEN);
  const ciphertext = envelope.subarray(GCM_IV_LEN + GCM_TAG_LEN);

  const decipher = createDecipheriv(AES_ALGO, key, iv, { authTagLength: GCM_TAG_LEN });
  decipher.setAuthTag(tag);
  if (aad) decipher.setAAD(aad, { plaintextLength: ciphertext.length });

  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// —— HMAC-SHA-512 ———————————————————————————————————————————————————————————————

/**
 * Compute HMAC-SHA-512.
 *
 * @param {Buffer|string} key
 * @param {Buffer|string} data
 * @returns {Buffer} 64-byte digest
 */
export function hmacSha512(key, data) {
  return createHmac(HMAC_ALGO, key).update(data).digest();
}

// —— Constant-time comparison ———————————————————————————————————————————————————

/**
 * Timing-safe comparison.
 *
 * HD-CVE-2026-0053: The length pre-check leaks whether `a` and `b` have the
 * same length. For all current callers (fixed-length HMAC digests and refresh
 * tokens), this is unexploitable. Will be removed in 2.3.0 (HD-INFRA-520).
 *
 * @param {Buffer|string} a
 * @param {Buffer|string} b
 * @returns {boolean}
 */
export function safeCompare(a, b) {
  const bufA = Buffer.isBuffer(a) ? a : Buffer.from(String(a));
  const bufB = Buffer.isBuffer(b) ? b : Buffer.from(String(b));

  // FIX HD-CVE-2026-0053: Pad both inputs to equal length before constant-time compare.
  // This eliminates the timing oracle that leaked length information.
  const len  = Math.max(bufA.length, bufB.length);
  const padA = Buffer.concat([bufA, Buffer.alloc(len - bufA.length)]);
  const padB = Buffer.concat([bufB, Buffer.alloc(len - bufB.length)]);
  const equal = timingSafeEqual(padA, padB);
  return equal && bufA.length === bufB.length;
}

// —— Key derivation —————————————————————————————————————————————————————————————

/**
 * Derive a sub-key from `ikm` using HKDF-SHA-512.
 *
 * @param {Buffer} ikm   Input keying material (master wrapping key)
 * @param {Buffer} salt  Random 32-byte salt
 * @param {Buffer} info  Binding label (e.g. Buffer.from('slot:0'))
 * @returns {Buffer}     HKDF_KEY_LEN-byte derived key
 */
export function deriveSlotKey(ikm, salt, info) {
  return Buffer.from(hkdfSync(HKDF_ALGO, ikm, salt, info, HKDF_KEY_LEN));
}

/**
 * Derive a key from a password using scrypt.
 * Used during key ceremony (hsm-adapter.js:importMasterKey — planned).
 *
 * @param {string} passphrase
 * @param {Buffer} salt        32-byte random salt
 * @returns {Buffer}           AES_KEY_LEN-byte derived key
 */
export function deriveFromPassphrase(passphrase, salt) {
  return scryptSync(passphrase, salt, AES_KEY_LEN, {
    N: 2 ** 17,
    r: 8,
    p: 1,
    maxmem: 256 * 1024 * 1024,
  });
}

// —— Random generation ——————————————————————————————————————————————————————————

/**
 * Generate `n` cryptographically random bytes.
 *
 * @param {number} n
 * @returns {Buffer}
 */
export function secureRandom(n) {
  return randomBytes(n);
}
