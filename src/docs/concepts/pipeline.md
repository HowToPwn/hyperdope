# Pipeline - How Hyperdope Works

Hyperdope organizes security research into **6 sequential phases**, mirroring the exact workflow of real-world researchers - from attack surface mapping to a complete disclosure package.

---

## Overview

```
Phase 0  hd_scan          ← No LLM required. Scan CVEs, secrets, hooks.
   ↓ CVE list, SBOM, secrets, hooks
Phase 1  hd_profile       ← LLM maps attack surface (STRIDE)
   ↓ surface categories, trust boundaries, data flows
Phase 2  hd_audit         ← LLM hunts source→sink, control gaps
   ↓ candidate vulnerabilities, chain candidates
Phase 3  hd_confirm       ← LLM generates PoCs
   ↓ exploit scripts, reliability rating, detection likelihood
Phase 4  hd_assess        ← LLM + math: CVSS v3.1
   ↓ CVSS vector + verified score, blast radius
Phase 5  hd_draft_ghsa    ← LLM drafts GHSA advisory
   ↓ advisory schema, remediation priority
Phase 6  hd_disclose      ← LLM generates disclosure package
   ↓ exec brief + technical advisory + vendor email

(optional)
  hd_verify               ← After vendor patch: confirm fix
   ↓ PATCHED / PARTIAL_FIX / STILL_VULNERABLE / CANNOT_VERIFY
```

---

## Running the Pipeline

### Option 1 - `hd_run` / `hd-run` (Recommended)

Runs all 6 phases automatically with context chaining and trimming handled under the hood:

```bash
# CLI
npx hd-run --agent agent.yaml --target https://github.com/org/repo

# MCP tool
hd_run(agent="agent.yaml", target="https://github.com/org/repo")
```

Session state is persisted to `.hyperdope-session-<timestamp>.json`. Resume if interrupted:

```bash
npx hd-run --agent agent.yaml \
  --target https://github.com/org/repo \
  --resume-from confirm \
  --session-file .hyperdope-session-20260825T141032.json
```

### Option 2 - Invoking Tools Individually

Invoke each phase individually in your MCP client, passing previous phase outputs into the `context` parameter:

```
# Step 1
result_profile = hd_profile(agent="agent.yaml", target="...")

# Step 2 - pass entire profile output into context
result_audit = hd_audit(
  agent="agent.yaml",
  target="...",
  context={"profile": result_profile.raw}   ← JSON string
)

# Step 3
result_confirm = hd_confirm(
  agent="agent.yaml",
  target="...",
  context={
    "profile": result_profile.raw,
    "audit":   result_audit.raw
  }
)
```

> **Note:** `context` accepts `{phase_name: raw_string}`. Values are **JSON strings** (raw output from the previous phase), not parsed objects. `hd_run` manages this automatically - which is why using `hd_run` is recommended over invoking tools manually.

---

## Context Trimming

Each phase trims context before dispatching to the LLM to prevent context window overflow:

- Preserves the full output of the **immediately preceding phase**
- Summarizes or truncates earlier phases
- Never trims output from the current phase

For example: when running `assess`, context will retain complete `confirm` and `audit` data, while `profile` may be truncated if too large.

---

## Prompt Injection Mitigation

All attacker-controlled content (target URLs, source file contents, outputs from prior phases) is encapsulated in XML tags:

```
<pipeline_data label="audit_findings">
  { ... JSON audit output ... }
</pipeline_data>
```

Each phase's system prompt instructs the model to treat everything inside `<pipeline_data>` strictly as **data for analysis**, never as actionable instructions. This prevents untrusted repositories from injecting commands into the agent.

---

## Phase-by-Phase Breakdown

### Phase 0 - `hd_scan` (No LLM Required)

**Input:** Path to directory containing lockfiles.

**Function:** Queries the OSV.dev batch API for all detected ecosystems. Scans for hardcoded secrets in configuration files. Analyzes npm lifecycle hooks.

**Supported Lockfiles:**

| Ecosystem | File |
|---|---|
| npm | `package-lock.json`, `package.json` |
| Python | `requirements.txt`, `poetry.lock`, `Pipfile.lock` |
| Go | `go.mod` |
| Rust | `Cargo.lock` |

**Key Output:**

```json
{
  "findings": [
    {
      "id":        "SCAN-GHSA-p6mc-m468-83gw",
      "package":   "lodash",
      "version":   "4.17.20",
      "ecosystem": "npm",
      "severity":  "HIGH",
      "summary":   "Prototype pollution in lodash",
      "fixed_in":  "4.17.21",
      "references": ["https://github.com/advisories/GHSA-p6mc-m468-83gw"]
    },
    {
      "id":          "SECRET-001",
      "type":        "AWS Access Key ID",
      "file":        ".env",
      "line":        12,
      "match_preview": "AKIA...[REDACTED]...XYZ",
      "severity":    "HIGH"
    }
  ],
  "meta": {
    "packages_scanned":      312,
    "vulnerabilities_found": 2,
    "secrets_found":         1,
    "hooks_found":           0,
    "ecosystems":            ["npm"]
  },
  "sbom": {
    "components": [
      { "name": "lodash", "version": "4.17.20", "ecosystem": "npm",
        "purl": "pkg:npm/lodash@4.17.20" }
    ]
  }
}
```

---

### Phase 1 - `hd_profile` (LLM)

**Input:** Target descriptor (URL, path, description).

**Function:** Maps the attack surface using STRIDE. Identifies data flows, trust boundaries, parsers, authentication mechanisms, deserialization sinks, supply chain dependencies, and LLM surfaces.

**Output:** Surface categories categorized by priority P0/P1/P2, STRIDE applicability, observable evidence, and attack vectors.

**Why run this first?** You cannot hunt vulnerabilities effectively without mapping what exists. Profile serves as the research brief guiding all subsequent phases.

---

### Phase 2 - `hd_audit` (LLM)

**Input:** Target + profile context.

**Function:** 5-step adversarial hunt:
1. Entry point inventory
2. Source → sink tracing
3. Control gap analysis (auth, validation, escaping, serialization)
4. Assumption violation (what does the code assume that an attacker can break?)
5. Chain candidate identification

**Output:** Candidate vulnerabilities with title, CWE, affected component, attack scenario, and severity estimate.

---

### Phase 3 - `hd_confirm` (LLM)

**Input:** Target + audit findings.

**Function:** Generates up to 3 PoCs per finding, ordered by exploitability. Each PoC includes:
- Step-by-step trigger sequence
- Sample payload / request
- Expected vs actual outcome
- Reliability rating: `deterministic` / `probabilistic` / `timing-dependent`
- Detection likelihood: `low` / `medium` / `high`

**Why before CVSS?** CVSS metrics (Attack Complexity, Privileges Required, User Interaction) are derived from observable PoC mechanics - not speculative estimates.

---

### Phase 4 - `hd_assess` (LLM + Math)

**Input:** Target + audit + confirm context.

**Function:** Assigns a CVSS v3.1 vector with per-metric chain-of-thought. The score is **calculated mathematically from the vector** - the LLM cannot hallucinate mismatched scores. Also evaluates blast radius, chaining potential, and scope (`S:C` when crossing security boundaries).

**Sample Output:**

```json
{
  "vulnerability_id": "HD-2026-001",
  "cvss_vector":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  "cvss_score":       9.1,
  "severity":         "critical",
  "reasoning": {
    "AV": "Network - reachable over internet without physical access",
    "AC": "Low - no special conditions required",
    "PR": "None - unauthenticated endpoint",
    "UI": "None - no victim interaction needed",
    "S":  "Unchanged - attacker cannot jump to other systems",
    "C":  "High - arbitrary file read leaks all server secrets",
    "I":  "High - arbitrary file write achieves RCE",
    "A":  "None - service remains available"
  }
}
```

---

### Phase 5 - `hd_draft_ghsa` (LLM)

**Input:** Target + audit + confirm + assess context.

**Function:** Generates a GitHub Security Advisory draft adhering to the GHSA schema:
- Package name + affected version range
- CWE IDs
- CVSS vector
- Description (executive summary + technical root cause)
- Remediation guidance
- Priority: P1 (7 days) / P2 (30 days) / P3 (90 days)
- Disclosure readiness checklist

---

### Phase 6 - `hd_disclose` (LLM)

**Input:** Full context from all previous phases.

**Function:** Generates a complete disclosure package:
1. **Executive brief** - 3–5 sentences tailored for CISOs / VPs of Engineering
2. **Full technical advisory** - root cause, PoC, impact, IoCs, remediation diff
3. **Vendor notification email** - professional tone with 90-day timeline table

---

### `hd_verify` - Patch Verification (LLM)

**When to run:** After the vendor releases a patch.

**Input:** Patch descriptor (commit SHA, version tag, diff URL) + audit/confirm/assess context.

**Methodology - 4 Core Questions:**
- **Q1:** What is the exact root cause? (function, file, failure condition)
- **Q2:** What did the patch change? Does it address the exact root cause site?
- **Q3:** Can the original PoC still trigger via alternate paths or encodings?
- **Q4:** Are there sibling call sites with identical patterns that the patch missed?

**Verdicts:**

| Verdict | Definition |
|---|---|
| `PATCHED` | Root cause is resolved across all call sites. PoC no longer works. |
| `PARTIAL_FIX` | Mitigates one vector but leaves bypasses or sibling sites unpatched. |
| `STILL_VULNERABLE` | Patch is missing or ineffective. PoC continues to work. |
| `CANNOT_VERIFY` | Insufficient information (missing diff/source) to determine status. |
