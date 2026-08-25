# Security Policy - hyperdope

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report via GitHub's private security advisory system:
**[Report a vulnerability](https://github.com/HowToPwn/hyperdope/security/advisories/new)**

---

## Trust Model

Understanding the trust model is required before submitting. Misclassifying a finding against the wrong boundary wastes everyone's time.

| Principal | Trust level |
| --- | --- |
| Operator | Full trust - controls `agent.yaml`, environment variables, Node options, working directory |
| LLM provider (Anthropic, OpenAI, etc.) | Untrusted network peer - responses are parsed, not executed |
| Scan target | Untrusted - the directory or repository being analysed |
| MCP client (Claude Desktop, etc.) | Semi-trusted - invokes tools with arguments; arguments are validated but not operator-level |

A finding that requires the attacker to already be the operator is **not a finding**. A finding that requires the attacker to control the LLM's output must demonstrate an exploitable consequence beyond the LLM producing unexpected text.

---

## Scope

### In scope

| Target | Qualifying finding class |
| --- | --- |
| MCP server (`src/server.js`) | Tool argument escapes validation and causes code execution or file access outside the declared target |
| Phase engine (`src/phases/`) | Prompt injection via scan target content that causes measurable data exfiltration or tool invocation outside expected phase flow |
| OSV scan module (`src/phases/scan.js`) | SSRF that reaches a non-public resource; path traversal that reads files outside the declared target directory with evidence |
| Session manager (`src/session.js`) | Session file readable by another local user on a multi-tenant host; path traversal to arbitrary file |
| Config loader (`src/config.js`) | YAML deserialization that achieves prototype pollution with exploitable downstream effect; path traversal via `agent` parameter |
| Provider adapters (`src/providers/`) | API key or credential present in logged output, error messages, or returned tool content under normal operation |
| Direct dependencies | CVE with CVSS v3.1 Base Score ≥ 8.5, confirmed reachable through hyperdope's actual call graph, with a working PoC demonstrating impact |

### Out of scope

The following are **closed without response** unless accompanied by a working PoC that proves exploitability through hyperdope specifically with no operator-level prerequisites:

- Any issue where the attacker prerequisite is write access to `agent.yaml`, environment variables, or Node startup flags - that is operator-level trust
- Issues in `src/internal/` - this directory is intentional dead code used for pipeline testing; findings there carry zero weight
- MCP tool parameter injection where the injecting party is the LLM itself - the LLM is already semi-trusted
- Vulnerabilities in LLM provider APIs - report directly to Anthropic, OpenAI, or Google
- Findings that require `NODE_ENV=development`, `--inspect`, or other debug flags not present in the published npm package
- Scanner output (Semgrep, CodeQL, Snyk, Trivy, Nuclei, Bandit, etc.) without manual triage confirming actual exploitability
- Direct dependency CVEs with CVSS < 8.5 or without a demonstrated reachable path through hyperdope's code
- Transitive dependency CVEs regardless of severity - we do not control their fix timelines
- Denial-of-service via resource exhaustion (token flooding, oversized payloads, OSV API abuse)
- Rate limiting or brute-force surface on provider APIs
- Missing HTTP security headers - hyperdope is an MCP stdio server, not an HTTP service
- Findings that only reproduce on a modified or locally-patched build, not against the published npm package
- Theoretical attack chains that require multiple independent low-probability conditions - model it, calculate the AC, and if it's AC:H the bar for PoC is higher, not optional
- Version disclosure in error messages
- Social engineering or attacks on contributors
- The LLM producing "harmful" security research content - hyperdope is a security tool; prompt engineering outputs are not vulnerabilities

---

## Submission Requirements

**Non-compliant reports are closed without response.** Every submission must include all five sections below.

### 1. Affected component

File path, function name, and line number(s) in the **published npm package** (not just the GitHub source). If the line numbers differ between source and published package, include both.

### 2. Root cause

One paragraph: the exact code path from attacker-controlled input to vulnerable sink, the missing or incorrect check, and the invariant that is violated. Reference the CWE (e.g. CWE-22, CWE-918, CWE-1333). "The server is vulnerable" is not a root cause.

### 3. Attacker model

State explicitly:
- What trust level the attacker holds (see Trust Model above)
- What prerequisites they need (local access, network position, MCP client access, etc.)
- What they do not need (e.g. "does not require operator credentials")

### 4. Working PoC

PoC must be:
- **Self-contained** - all code, commands, and setup in the report; no external dependencies beyond the npm package itself
- **Deterministic** - reliably reproducible; timing-dependent PoCs must include a statistical reproduction rate
- **Evidence-producing** - must generate unambiguous proof of exploitation: a file created, data exfiltrated to stdout/stderr, a process spawned, or a measurable incorrect computation
- **Tested against the published package** - run `npm install -g hyperdope` and reproduce against that, not a local dev build

**Required PoC structure:**

```
## Attacker prerequisites
[Trust level, access required, environment]

## Steps
1. ...
2. ...

## Evidence of exploitation
[Exact output, file content, or observable state that proves the finding]

## Evidence against a patched build
[What the fixed version shows - e.g. error thrown, access denied]
```

### 5. CVSS v3.1 vector string

Provide `CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_` with justification for each metric. We verify independently. Vectors that don't match the described attacker model will be rescored - if our rescore changes the severity band, our SLA applies to our score, not yours.

---

## Severity Thresholds and Response SLA

| Severity | CVSS Score | Acknowledgement | Fix target |
| --- | --- | --- | --- |
| Critical | 9.0 – 10.0 | 24 hours | 7 days |
| High | 7.0 – 8.9 | 48 hours | 30 days |
| Medium | 4.0 – 6.9 | 72 hours | 90 days |
| Low | 0.1 – 3.9 | 7 days | Best effort |

SLA starts from first acknowledgement, not submission date.

**Reporter unresponsive:** if we cannot reproduce the issue and receive no response to a clarification request within 21 days, the report is closed. Researchers may reopen with additional detail.

**If we miss an SLA:** you may request a status update. If no response within 7 days of that request, you may disclose with 72 hours notice.

---

## Duplicate and Variant Policy

- First reporter only is credited for a given root cause
- A finding that shares the same root cause as an open or patched issue is a duplicate regardless of the affected function or file - fix the root, all variants close
- A variant that introduces a materially different exploit primitive (e.g. read → write) is treated as a distinct finding with its own SLA

---

## Disclosure Policy

- We follow **90-day coordinated disclosure** from first acknowledgement
- We will not request embargo beyond 120 days total without your explicit agreement
- We will credit you in the fix commit, release notes, and Hall of Fame (unless you request anonymity)
- We will open a GitHub Security Advisory and request a CVE ID for confirmed Critical/High findings
- Partial fixes (mitigations that reduce severity but do not close the root cause) are disclosed as such - we will not represent a mitigation as a complete fix

**We do not pay monetary bounties.** This is an open-source security research tool. Recognition, attribution, and a Hall of Fame entry are what we offer.

---

## What We Will Not Do

- Pursue legal action against researchers who follow this policy
- Contact your employer, ISP, or any third party about a good-faith disclosure
- Silently fix a reported vulnerability without crediting the reporter
- Close a valid finding because it is inconvenient or makes the project look bad

**Safe Harbor:** Security research conducted in accordance with this policy is authorized. We consider it a contribution.

---

## Hall of Fame

Researchers who report confirmed Critical or High findings are listed here: https://hyperdope.ai.studio/

*No entries yet - be the first.*

---

*Last updated: 2026-08-25*
