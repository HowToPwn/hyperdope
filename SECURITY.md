# Security Policy — hyperdope

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report via GitHub's private security advisory system:
**[Report a vulnerability](https://github.com/HowToPwn/hyperdope/security/advisories/new)**

---

## Scope

### In scope

| Target | Examples |
| --- | --- |
| MCP server source (`src/`) | Arbitrary code execution, auth bypass, path traversal, prototype pollution |
| Provider adapters (`src/providers/`) | API key exposure, credential leakage through error messages or logs |
| Session file handling (`src/session.js`) | Unauthorized read/write of `.hyperdope/sessions/`, path traversal to arbitrary files |
| Phase prompt engine (`src/phases/`) | Prompt injection that causes the server to exfiltrate caller data or execute unintended tool calls |
| OSV scan module (`src/phases/scan.js`) | SSRF via crafted target path, dependency confusion via package name manipulation |
| CVSS calculator (`src/cvss.js`) | Logic errors producing incorrect scores that cause systematic misclassification of severity |
| Config loader (`src/config.js`) | Env var injection, YAML deserialization issues, path traversal via `agent` parameter |
| Direct dependencies only | CVE with CVSS v3.1 Base Score ≥ 7.0, confirmed to be reachable through hyperdope's code paths |

### Out of scope

The following will be **rejected without acknowledgement** unless accompanied by a working PoC that proves exploitability through hyperdope specifically:

- Vulnerabilities in LLM provider APIs (Anthropic, OpenAI, Google, etc.) — report directly to them
- Issues that require a compromised or malicious `agent.yaml` supplied by the operator
- Rate limiting, throttling, or brute-force surface on provider APIs
- Denial-of-service via resource exhaustion (token flooding, large payloads)
- Social engineering, phishing, or attacks on hyperdope contributors
- Scanner output (Burp Suite, Nuclei, Semgrep, Bandit, etc.) without manual triage and confirmed exploitability
- Theoretical vulnerabilities without a working PoC — "this *could* lead to..." is not a finding
- Vulnerabilities in `node_modules` already publicly listed in NVD/OSV without a confirmed reachable code path
- Self-XSS or issues requiring the attacker to already have operator-level access
- Missing HTTP security headers (hyperdope is an MCP server, not an HTTP service)
- Version disclosure in error messages
- Issues in `agent.example.yaml` that only affect operators who ignore documented security guidance

---

## Submission Requirements

**Non-compliant reports will be closed without response.** Every submission must include:

### 1. Affected component
File path, function name, and line number(s). "The server is vulnerable" is not a valid component reference.

### 2. Root cause
One paragraph: the exact code path, the missing or incorrect check, and the invariant that is violated.

### 3. Working PoC

PoC must be:
- **Self-contained** — all code, commands, and setup steps in the report
- **Deterministic** — reliably reproducible; not dependent on specific timing unless the vulnerability is inherently a race condition
- **Evidence-producing** — must generate observable, unambiguous proof of exploitation (file created, data exfiltrated, process spawned, error message revealing sensitive data, etc.)
- **Non-destructive** — demonstrates impact without permanently harming the test environment

**Minimum PoC structure:**
```
## Prerequisites
[Environment, Node version, dependencies]

## Steps
1. ...
2. ...

## Expected output (exploited)
[Exact output or state that proves exploitation]

## Expected output (not exploited / patched)
[What a fixed version shows]
```

### 4. Impact statement
What does an attacker achieve? Be specific: "read arbitrary files from the filesystem" is acceptable. "could potentially be misused" is not.

### 5. CVSS v3.1 vector string
Provide `CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_`. We will independently verify using the mathematical calculator. Submissions with vector strings that don't match the described impact will be rescored.

---

## Severity Thresholds and Response SLA

| Severity | CVSS Score | Acknowledgement | Fix Target |
| --- | --- | --- | --- |
| Critical | 9.0 – 10.0 | 24 hours | 7 days |
| High | 7.0 – 8.9 | 48 hours | 30 days |
| Medium | 4.0 – 6.9 | 72 hours | 90 days |
| Low | 0.1 – 3.9 | 7 days | Best effort |

SLA starts from the date of first acknowledgement, not submission date.

**If we miss an SLA:** you may request a status update. If no response within 7 days of a status request, you may disclose with 72 hours notice.

---

## Disclosure Policy

- We follow **90-day coordinated disclosure**
- We will work with you to understand and reproduce the issue before requesting embargo extensions
- We will not request embargo beyond 120 days total without your explicit agreement
- We will credit you in the fix commit, release notes, and Hall of Fame (unless you request anonymity)
- We will open a GitHub Security Advisory and request a CVE ID for confirmed Critical/High findings

**We do not pay monetary bounties.** This is an open-source project. Recognition, attribution, and a detailed Hall of Fame entry are the rewards we offer.

---

## What We Will NOT Do

- We will not pursue legal action against researchers who follow this policy
- We will not contact your employer, ISP, or any third party about a good-faith disclosure
- We will not silently fix a reported vulnerability without crediting the reporter

**Safe Harbor:** Security research conducted in accordance with this policy is authorized. We consider it a contribution to the project.

---

## Hall of Fame

Researchers who report valid Critical or High findings are listed here.

*No entries yet — be the first.*

---

## Non-Qualifying Submissions

Reports will be **closed immediately** if they consist of:

- Output from automated scanners without manual validation
- CVE IDs for dependencies without demonstrating a reachable, exploitable path through hyperdope's code
- Issues that require the attacker to control the `agent.yaml` file (operator-level trust)
- Findings already reported by another researcher (first reporter only)
- Issues in the LLM provider's API or infrastructure
- Missing `Content-Security-Policy` or similar HTTP headers (not applicable to an MCP stdio server)
- The LLM producing "harmful" content — hyperdope is a security research tool; prompt engineering is not a vulnerability

---

*Last updated: 2026-08-25*
