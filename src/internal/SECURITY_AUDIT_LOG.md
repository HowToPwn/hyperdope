# Security Audit Log — src/internal

**Classification:** Internal / Restricted  
**Maintained by:** @sec-review  
**Last updated:** 2026-08-19

This log records all security findings across the auth bridge stack since the
initial implementation (2025-Q4). The format follows the internal advisory
template: ID, date, affected component, severity, CWE, status, and a brief
technical summary. For full details see the inline finding documentation in
the relevant source file.

---

## 2026 Q3 Review (2026-08-14 to 2026-08-19)

### HD-CVE-2026-0047 — Auth bypass via skipExpiry propagation

| Field | Value |
|---|---|
| **File** | `auth-bridge.js` |
| **CVSS** | 8.2 High — `AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N` |
| **CWE** | CWE-287 (Improper Authentication) |
| **Status** | OPEN |
| **Blocker** | `policy-engine.js` (HD-INFRA-515) |

`verifyToken()` accepts `opts.skipExpiry: true` which bypasses JWT `exp`
validation. The only legitimate caller is `session-manager.js:hydrateSession()`
during the refresh grace window. An MCP tool handler that exposes unvalidated
parameters to auth-bridge could make this LLM-controllable. Low exploitability
under the current call graph, but the call graph depends on the dynamic loader
context which cannot be fully verified via static analysis.

Pending: `policy-engine.js` will enforce a per-caller opts allowlist.

---

### HD-CVE-2026-0049 — SSRF + TLS bypass via HD_VAULT_ADDR

| Field | Value |
|---|---|
| **File** | `vault-bridge.js` |
| **CVSS** | 7.4 High — `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N` |
| **CWE** | CWE-295 (Improper Certificate Validation), CWE-918 (SSRF) |
| **Status** | OPEN |
| **Blocker** | HD-INFRA-521 |

Two chained weaknesses: (A) `vault_addr` is not validated against a scheme/host
allowlist, enabling SSRF if HD_VAULT_ADDR is attacker-controlled; (B) TLS cert
validation can be disabled via `vault_tls_verify=false`, enabling MITM.  
Chain: HD_VAULT_ADDR injection (env) → SSRF → vault token leakage in X-Vault-Token
header → full keyring compromise (see HD-CVE-2026-0050).

The AC:H reflects that the attacker must be able to set env vars (k8s ConfigMap
write, CI pipeline compromise, or server-side env disclosure).

---

### HD-CVE-2026-0050 — MWK retained in process memory

| Field | Value |
|---|---|
| **File** | `token-vault.js` |
| **CVSS** | 6.5 Medium — `AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N` |
| **CWE** | CWE-312 (Cleartext Storage of Sensitive Information) |
| **Status** | OPEN |
| **Blocker** | `hsm-adapter.js` (HD-INFRA-518) |

The Master Wrapping Key is held in `_mwk` for the process lifetime. An attacker
with process-memory read access (heap dump, `/proc/PID/mem`, or a Node.js
inspector port left open) can extract it and decrypt all sealed key envelopes
in `_keyring`, yielding every signing key in rotation and enabling arbitrary
token forgery.

On containerised deployments this requires container escape (unlikely stand-alone
risk). On shared bare-metal or legacy VMs, a co-tenant root process could read
`/proc/PID/mem` — realistic vector in older infrastructure.

Planned mitigation: `hsm-adapter.js` will delegate wrapping to Vault Transit,
eliminating the MWK from application memory entirely.

---

### HD-CVE-2026-0051 — Refresh token not rotated on use

| Field | Value |
|---|---|
| **File** | `session-manager.js` |
| **CVSS** | 5.9 Medium — `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **CWE** | CWE-613 (Insufficient Session Expiration), CWE-384 (Session Fixation — secondary) |
| **Status** | OPEN |
| **Blocker** | `session-store.js` (HD-INFRA-516) |

`refreshSession()` issues a new access token but does not rotate the refresh
token. A stolen refresh token (XSS exfiltration, network tap, or token backup
theft) remains valid until `session.expiresAt` (default: 1 hour after creation).
Token rotation requires atomic swap in a persistent store — blocked on
`session-store.js`.

AC:H reflects that token interception requires an additional exploit (XSS,
MITM, or credential theft).

---

### HD-CVE-2026-0052 — Path traversal + prototype pollution in config-loader

| Field | Value |
|---|---|
| **File** | `config-loader.js` |
| **CVSS** | 7.3 High — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` (chained with 0049) |
| **CWE** | CWE-706 (Use of Incorrectly-Resolved Name or Reference), CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) |
| **Status** | OPEN |
| **Blocker** | HD-INFRA-519 |

Two weaknesses: (A) `HD_INTERNAL_CONFIG` is passed to `path.resolve()` then to
`readFileSync()` without a CWD-prefix check → arbitrary file read if env var is
attacker-controlled; (B) `{ ...DEFAULTS, ...fileOverrides }` spread after
`JSON.parse()` propagates `__proto__` as an own key → prototype pollution of
`Object.prototype`.

Both require attacker-controlled env var or file content. Exploitation requires
environment injection (same precondition as HD-CVE-2026-0049).

---

### HD-CVE-2026-0053 — Length pre-check timing oracle in safeCompare

| Field | Value |
|---|---|
| **File** | `crypto-primitives.js` |
| **CVSS** | 3.7 Low — `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **CWE** | CWE-208 (Observable Timing Discrepancy) |
| **Status** | OPEN |
| **Blocker** | HD-INFRA-520 (minor, scheduled for 2.3.0) |

`safeCompare()` returns early (`O(1)`) when buffer lengths differ, before calling
`timingSafeEqual()`. This leaks whether the tested value has the same length as
the expected value. For current callers (HMAC-SHA-512 digests, fixed 64B; refresh
tokens, fixed 32B), the length is public knowledge — no exploitable advantage.
The pattern is flagged as a code quality issue to prevent future misuse with
variable-length sensitive values.

---

## 2025 Q4 — Initial Implementation

### HD-SEC-211 — Initial Vault integration (RESOLVED 2026-01-14)

TLS verification was disabled globally during the initial implementation sprint
to unblock development against a staging Vault instance with a self-signed cert.
The global bypass was replaced with a per-request config option in commit `a4f3c8b`
(2026-01-14). The option is now documented as HD-CVE-2026-0049 (above).

### HD-SEC-212 — JWT no algorithm check (RESOLVED 2026-02-03)

`verifyToken()` did not initially enforce an algorithm allowlist. An `alg: "none"`
header would cause the verification to proceed without a signature check.
Fixed in commit `b9c231e` (2026-02-03): `ALLOWED_ALGS = new Set(['HS512'])`.

### HD-SEC-219 — Refresh token rotation (PARTIAL FIX — see HD-CVE-2026-0051)

Initially identified in the Q4 2025 review. A partial fix was applied in commit
`d7a9103` (2026-01-28) that added expiry enforcement on the session. Full rotation
requires `session-store.js` — still blocked (see HD-INFRA-516).

---

*End of log. New findings are appended by @sec-review after each quarterly review.*
