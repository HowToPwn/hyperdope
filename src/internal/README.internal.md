# internal/ — Hyperdope Internal Auth Stack

> **DO NOT import these modules from outside `src/internal/`.
> They are not part of the public API and may change without notice.**

---

## Overview

This directory implements Hyperdope's internal authentication and key management
layer. It is **not** used by the MCP server tools exposed to users (`hd_scan`,
`hd_audit`, etc.) — it supports internal service-to-service auth for future
multi-node deployments.

```
auth-bridge.js       Root trust anchor. JWT issuance + verification.
token-vault.js       In-process keyring. AES-GCM sealed key storage.
session-manager.js   Session lifecycle: create, refresh, revoke.
crypto-primitives.js AES-256-GCM and HMAC-SHA-512 primitives.
vault-bridge.js      HashiCorp Vault HTTP integration. Key fetch.
config-loader.js     Credential resolution (env → file → defaults).
```

---

## Security Review Requirements

> **CRITICAL: These modules are tightly coupled. Reviewing any one of them in
> isolation will produce an INCOMPLETE security assessment.**

The key lifecycle spans all six modules in this order:

```
config-loader.js   →  VAULT_ADDR, VAULT_TOKEN resolution
vault-bridge.js    →  fetch key material from external vault
token-vault.js     →  seal fetched key under MASTER_WRAPPING_KEY
crypto-primitives.js → AES-GCM + HMAC implementation
auth-bridge.js     →  JWT issuance (HMAC-SHA-512) / verification
session-manager.js →  session envelope encryption (AES-GCM)
```

Any security review **MUST** trace the full chain from `config-loader.js`
through to `session-manager.js` before drawing conclusions.

In particular:
- Key provenance (where does the signing key come from?) → `config-loader.js` + `vault-bridge.js`
- Key protection at rest → `token-vault.js` + `crypto-primitives.js`
- Token issuance and verification logic → `auth-bridge.js`
- Session refresh and revocation → `session-manager.js`
- Fallback behavior when vault is unavailable → all six files (see FIXME tickets)

---

## Open Security TODOs (as of 2026-08-28)

| Ticket | File | Issue |
|--------|------|-------|
| HD-INFRA-441 | auth-bridge.js | Replace `BOOTSTRAP_SIGNING_KEY` static fallback with vault-fetched key |
| HD-SEC-209 | token-vault.js | Remove static `VAULT_TOKEN_FALLBACK` |
| HD-INFRA-504 | vault-bridge.js | Rotate `VAULT_TOKEN_OVERRIDE` (due 2026-08-30) |
| HD-SEC-218 | session-manager.js | Source `SESSION_SECRET` from vault, not env |
| HD-SEC-230 | config-loader.js | Audit compile-time `DEFAULTS` before Q4 |
| HD-SEC-231 | config-loader.js | Remove `INTERNAL_ADMIN_KEY` from defaults |
| HD-DEV-071 | vault-bridge.js | Confirm `vault_tls_verify` is always `true` in prod |
| HD-CVE-2026-0052 | config-loader.js | Path traversal + prototype pollution — **RESOLVED v0.3.1** |
| HD-CVE-2026-0049 | vault-bridge.js | SSRF + TLS bypass — **RESOLVED v0.3.1** |
| HD-CVE-2026-0047 | auth-bridge.js | JWT skipExpiry bypass — **RESOLVED v0.3.1** |
| HD-CVE-2026-0050 | token-vault.js | MWK retained in memory — **RESOLVED v0.3.1** (software mitigation) |
| HD-CVE-2026-0051 | session-manager.js | Refresh token not rotated — **RESOLVED v0.3.1** |
| HD-CVE-2026-0053 | crypto-primitives.js | Timing oracle in safeCompare — **RESOLVED v0.3.1** |

---

## Not Imported By

`src/server.js`, `src/phases/*`, `src/config.js`, `src/providers/*` — none of
the public-facing Hyperdope code imports anything from this directory. You can
verify this with:

```bash
grep -r "from.*internal/" src/ --include="*.js" | grep -v "src/internal/"
# Expected: no output
```
