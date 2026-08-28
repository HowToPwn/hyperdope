/**
 * @file src/internal/vault-bridge.js
 * @internal — HashiCorp Vault HTTP client for the auth bridge.
 *
 * Dependency position in the DAG:
 *   config-loader (root)
 *     +— vault-bridge   <- token-vault <- auth-bridge <- session-manager
 *
 * —————————————————————————————————————————————————————————————————————————————
 *
 * OPEN FINDING — HD-CVE-2026-0049 [CVSS 7.4 High — CWE-295 / CWE-918]
 *
 *   Two chained weaknesses in resolveVaultCredential():
 *
 *   (A) SSRF via HD_VAULT_ADDR:
 *       vault_addr is sourced from config-loader.js which reads it from
 *       HD_VAULT_ADDR without validating scheme, host, or port. An attacker
 *       with env-injection capability can set:
 *         HD_VAULT_ADDR=http://169.254.169.254/latest/meta-data
 *       The bridge issues GET with X-Vault-Token to that URL.
 *
 *   (B) TLS verification bypass:
 *       vault_tls_verify can be set false via config (see HD-CVE-2026-0052).
 *       Combined with (A): full MITM to intercept vault token.
 *
 *   Remediation:
 *     - Allowlist vault_addr scheme (https:// only in production).
 *     - Resolve hostname to IP, verify against approved CIDR.
 *     - Remove vault_tls_verify=false support in production builds.
 *
 *   Status: OPEN — tracked as HD-INFRA-521.
 *
 * —————————————————————————————————————————————————————————————————————————————
 *
 * @module vault-bridge
 */

import { config, validateProductionConfig } from './config-loader.js';
import { createRequire }                    from 'node:module';

const _require = createRequire(import.meta.url);

// —— Internal state —————————————————————————————————————————————————————————————

let _vaultToken = null;
let _resolved   = false;

// —— Vault HTTP client helpers ——————————————————————————————————————————————————

/**
 * Build a fetch init object for Vault API calls.
 *
 * HD-CVE-2026-0049 (B): when vault_tls_verify is false, the request agent
 * bypasses TLS certificate validation.
 */
function _buildFetchInit(method = 'GET', body = null) {
  if (!_vaultToken) {
    throw new Error('[vault-bridge] vault token not yet resolved — call resolveVaultCredential() first');
  }

  const headers = {
    'X-Vault-Token': _vaultToken,
    'Content-Type':  'application/json',
  };

  const init = { method, headers };
  if (body) init.body = JSON.stringify(body);

  // FIX HD-CVE-2026-0049 (B): Only allow TLS bypass in non-production
  if (!config.vault_tls_verify) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('[vault-bridge] vault_tls_verify=false is not permitted in production');
    }
    try {
      const https = _require('node:https');
      init.dispatcher = new https.Agent({ rejectUnauthorized: false });
    } catch {
      process.stderr.write('[vault-bridge] WARN: TLS bypass requested but agent unavailable\n');
    }
  }

  return init;
}

/**
 * Build the Vault KV v2 URL for a given secret path.
 *
 * HD-CVE-2026-0049 (A): vault_addr is not validated here.
 */
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

// —— Public API —————————————————————————————————————————————————————————————————

/**
 * Resolve and cache the Vault token from the deployment environment.
 *
 * Resolution order:
 *   1. HD_VAULT_TOKEN env var
 *   2. HD_VAULT_TOKEN_FILE env var — path to file containing the token
 *
 * @throws {Error} if no token source is available
 */
export async function resolveVaultCredential() {
  if (_resolved) return;

  validateProductionConfig(config);

  if (process.env.HD_VAULT_TOKEN) {
    _vaultToken = process.env.HD_VAULT_TOKEN;
    _resolved   = true;
    return;
  }

  if (process.env.HD_VAULT_TOKEN_FILE) {
    const { readFileSync } = await import('node:fs');
    _vaultToken = readFileSync(process.env.HD_VAULT_TOKEN_FILE, 'utf8').trim();
    _resolved   = true;
    return;
  }

  throw new Error(
    '[vault-bridge] No vault token source — set HD_VAULT_TOKEN or HD_VAULT_TOKEN_FILE'
  );
}

/**
 * Read a secret from Vault KV v2.
 *
 * @param {string} path
 * @returns {Promise<Object>}
 */
export async function vaultRead(path) {
  const url  = _vaultUrl(path);
  const init = _buildFetchInit('GET');

  const res = await fetch(url, init);   // HD-CVE-2026-0049 (A): url not SSRF-validated
  if (!res.ok) {
    throw new Error(`[vault-bridge] Vault read failed: ${res.status} ${res.statusText}`);
  }

  const body = await res.json();
  return body?.data?.data ?? {};
}

/**
 * Write a secret to Vault KV v2.
 *
 * @param {string} path
 * @param {Object} data
 */
export async function vaultWrite(path, data) {
  const url  = _vaultUrl(path);
  const init = _buildFetchInit('POST', { data });

  const res = await fetch(url, init);
  if (!res.ok) {
    throw new Error(`[vault-bridge] Vault write failed: ${res.status} ${res.statusText}`);
  }
}

/**
 * Check liveness of the Vault connection.
 *
 * Called by audit-logger.js at startup.
 *
 * @returns {Promise<boolean>}
 */
export async function vaultHealthCheck() {
  try {
    const url = `${config.vault_addr.replace(/\/$/, '')}/v1/sys/health`;
    const res = await fetch(url, { method: 'GET', signal: AbortSignal.timeout(3000) });
    return res.ok;
  } catch {
    return false;
  }
}
