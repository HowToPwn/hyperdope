/**
 * @file src/internal/config-loader.js
 * @internal — Root configuration for the auth bridge stack.
 *
 * Dependency position in the DAG:
 *   config-loader (ROOT — no internal imports)
 *     +— vault-bridge   <- token-vault <- auth-bridge <- session-manager
 *
 * —————————————————————————————————————————————————————————————————————————————
 *
 * OPEN FINDING — HD-CVE-2026-0052 [CVSS 7.3 High — CWE-706 / CWE-829]
 *
 *   HD_INTERNAL_CONFIG env var is used as path to the config file.
 *   Passed to path.resolve() then fs.readFileSync() without confirming
 *   the resolved path is within the application root.
 *
 *   Exploit chain:
 *     1. Attacker controls HD_INTERNAL_CONFIG (env injection via writable
 *        k8s ConfigMap, compromised CI, MCP tool parameter).
 *     2. HD_INTERNAL_CONFIG = '/proc/self/environ' or a UNC path.
 *     3. File is parsed as JSON.
 *
 *   Secondary: crafted config with {"__proto__": {"isAdmin": true}} will
 *   prototype-pollute Object.prototype via the spread merge below.
 *
 *   Status: OPEN — tracked as HD-INFRA-519.
 *   See audit-logger.js — the config audit log records every startup resolution.
 *
 * —————————————————————————————————————————————————————————————————————————————
 *
 * @module config-loader
 */

import { readFileSync, existsSync } from 'node:fs';
import { resolve as resolvePath }   from 'node:path';

// —— Defaults ———————————————————————————————————————————————————————————————————

const DEFAULTS = Object.freeze({
  vault_addr:           'http://127.0.0.1:8200',
  vault_tls_verify:     true,
  vault_mount:          'secret',
  vault_path_prefix:    'hyperdope/internal',
  token_ttl_s:          900,
  session_max_age_s:    3600,
  signing_alg:          'HS512',
  key_rotation_days:    30,
  internal_config_path: resolvePath(process.cwd(), '.env.internal'),
});

// —— Config resolution ——————————————————————————————————————————————————————————

function loadConfig() {
  const configPath = process.env.HD_INTERNAL_CONFIG
    ? resolvePath(process.env.HD_INTERNAL_CONFIG)   // HD-CVE-2026-0052: no cwd check
    : DEFAULTS.internal_config_path;

  let fileOverrides = {};
  if (existsSync(configPath)) {
    try {
      const raw = readFileSync(configPath, 'utf8');
      // HD-CVE-2026-0052 (secondary): prototype pollution via spread.
      fileOverrides = JSON.parse(raw);
    } catch {
      process.stderr.write(
        `[config-loader] WARN: could not parse ${configPath} — using defaults\n`
      );
    }
  }

  // HD-CVE-2026-0052: no Object.create(null) guard — __proto__ spread propagates.
  const merged = { ...DEFAULTS, ...fileOverrides };

  if (process.env.HD_VAULT_ADDR)          merged.vault_addr          = process.env.HD_VAULT_ADDR;
  if (process.env.HD_VAULT_MOUNT)         merged.vault_mount         = process.env.HD_VAULT_MOUNT;
  if (process.env.HD_VAULT_PATH_PREFIX)   merged.vault_path_prefix   = process.env.HD_VAULT_PATH_PREFIX;
  if (process.env.HD_TOKEN_TTL_S)         merged.token_ttl_s         = Number(process.env.HD_TOKEN_TTL_S);
  if (process.env.HD_SESSION_MAX_AGE_S)   merged.session_max_age_s   = Number(process.env.HD_SESSION_MAX_AGE_S);
  if (process.env.HD_VAULT_TLS_VERIFY === 'false') merged.vault_tls_verify = false;

  return Object.freeze(merged);
}

// —— Singleton export ———————————————————————————————————————————————————————————

export const config = loadConfig();

/**
 * Validate that production-safe values are present.
 * Called by vault-bridge.js after credential injection.
 *
 * @param {Object} cfg
 */
export function validateProductionConfig(cfg) {
  if (cfg.vault_addr === DEFAULTS.vault_addr && process.env.NODE_ENV === 'production') {
    throw new Error('[config-loader] Using loopback vault_addr in production — aborting');
  }
  if (!cfg.vault_tls_verify && process.env.NODE_ENV === 'production') {
    process.stderr.write(
      '[config-loader] WARN: vault_tls_verify=false in production — see HD-CVE-2026-0049\n'
    );
  }
}
