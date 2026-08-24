<div align="center">

![image](src/photos/image.png)

**MCP Server for Adversarial Security Research**

![npm](https://img.shields.io/npm/v/hyperdope?style=for-the-badge&color=crimson&logo=npm)
![Node](https://img.shields.io/badge/Node-20%2B-green?style=for-the-badge&logo=nodedotjs)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge&logo=opensourceinitiative)
![MCP](https://img.shields.io/badge/Protocol-MCP-purple?style=for-the-badge)
![ESM](https://img.shields.io/badge/Module-ESM-orange?style=for-the-badge)

A 6-phase agentic security research pipeline exposed as MCP tools - from attack surface profiling to coordinated disclosure. Runs inside Claude Code, Cursor, or any MCP host. Bring your own LLM.

[Installation](#installation) · [Quick Start](#quick-start) · [Agent Config](#agent-config) · [Pipeline](#pipeline) · [Tools](#tools) · [Session Resume](#session-resume) · [Providers](#providers) · [Troubleshooting](#troubleshooting) · [Disclaimer](#disclaimer)

</div>

---

<a id="installation"></a>
## Installation

**Global install (recommended)**

```bash
npm install -g hyperdope
```

**Run without installing**

```bash
npx hyperdope
```

**Dev / local**

```bash
git clone https://github.com/your-org/hyperdope.git
cd hyperdope
npm install
node bin/hyperdope.js
```

---

<a id="quick-start"></a>
## Quick Start

**Step 1 - Copy the example agent config**

```bash
cp agent.example.yaml agent.yaml
# Edit agent.yaml: set provider, model, and API key
```

**Step 2 - Register with your MCP host**

For Claude Code - add to `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "hyperdope": {
      "command": "npx",
      "args": ["hyperdope"],
      "env": {
        "CLAUDE_API_KEY": "sk-ant-..."
      }
    }
  }
}
```

For global registration, use `~/.claude/claude_desktop_config.json` with the same structure.

If running from a local clone, replace `"npx"` + `"args": ["hyperdope"]` with:

```json
"command": "node",
"args": ["/absolute/path/to/hyperdope/bin/hyperdope.js"]
```

**Step 3 - Run the full pipeline**

```json
{
  "tool": "hd_run",
  "arguments": {
    "agent": "./agent.yaml",
    "target": "https://github.com/example/target-repo"
  }
}
```

That's it. Hyperdope runs all 6 phases sequentially, chains context automatically, and writes a session file to `.hyperdope/sessions/`.

---

<a id="agent-config"></a>
## Agent Config

Copy `agent.example.yaml` to `agent.yaml`. Hyperdope resolves it in this order:

1. `--agent path/to/agent.yaml` CLI flag
2. `HYPERDOPE_AGENT` environment variable
3. `./agent.yaml` in the current working directory
4. Error with instructions

**Full annotated schema:**

```yaml
# ─── Provider ────────────────────────────────────────────────────────────────
provider: claude          # claude | openai | gemini | ollama | glm | kimi | qwen
model: claude-sonnet-4-6
api_key: ${CLAUDE_API_KEY}    # ${VAR_NAME} → resolved from env at runtime
base_url: ~               # optional: override for openai-compatible endpoints

# ─── Generation parameters ───────────────────────────────────────────────────
max_tokens: 8192
temperature: 0.2

# ─── Phase prompt overrides (all optional) ───────────────────────────────────
# Hyperdope ships production-grade prompts for every phase.
# Override any phase's system prompt or user prefix here.
# Set to ~ to use the built-in default.
phases:
  profile:
    system: "You are a senior security researcher..."   # replaces built-in system prompt
    user_prefix: "Profile the following target: "        # prepended before target string
  audit:
    system: ~
    user_prefix: ~
  confirm:
    system: ~
    user_prefix: ~
  assess:
    system: ~
    user_prefix: ~
  draft_ghsa:
    system: ~
    user_prefix: ~
  disclose:
    system: ~
    user_prefix: ~
```

**Environment variable resolution** - any `${VAR}` reference in the YAML is resolved at runtime. Missing variables throw with the variable name in the error message.

---

<a id="pipeline"></a>
## Pipeline

```
Target descriptor
      │
      ▼
┌─────────────┐
│  hd_profile │  Phase 1 - Map attack surface: trust boundaries, parsers,
│             │            deserialization, supply chain, auth flows, LLM surfaces
└──────┬──────┘
       │ context →
       ▼
┌─────────────┐
│  hd_audit   │  Phase 2 - Vulnerability hunt: OWASP Top 10, SANS 25,
│             │            LLM Top 10, reasoning per surface category
└──────┬──────┘
       │ context →
       ▼
┌─────────────┐
│  hd_confirm │  Phase 3 - PoC generation: minimal, self-contained,
│             │            deterministic proof-of-concept per finding
└──────┬──────┘
       │ context →
       ▼
┌─────────────┐
│  hd_assess  │  Phase 4 - CVSS v3.1 scoring (chain-of-thought per metric),
│             │            CWE classification, severity label
└──────┬──────┘
       │ context →
       ▼
┌──────────────────┐
│  hd_draft_ghsa   │  Phase 5 - GitHub Security Advisory draft
│                  │            following the GHSA schema exactly
└──────┬───────────┘
       │ context →
       ▼
┌─────────────┐
│  hd_disclose│  Phase 6 - Coordinated disclosure package:
│             │            executive brief · technical advisory · vendor email
└─────────────┘
       │
       ▼
.hyperdope/sessions/{timestamp}.json
```

Each phase's output `context` field is the exact input for the next phase's `context` argument. `hd_run` handles this automatically. Individual tools can be called standalone for custom workflows.

---

<a id="tools"></a>
## Tools

### `hd_profile` - Phase 1: Attack Surface Profile

Maps the target's complete attack surface across all relevant categories.

**What it covers:** trust boundaries, parser differentials, deserialization paths, supply chain dependencies, authentication and authorization flows, LLM-specific surfaces (prompt injection entry points, tool call abuse, RAG poisoning, agentic multi-hop chains), file system race conditions, cryptographic weaknesses, SSRF-reachable internal endpoints.

**Input**
```json
{
  "agent": "./agent.yaml",
  "target": "https://github.com/example/repo",
  "context": {}
}
```

**Output**
```json
{
  "phase": "profile",
  "status": "complete",
  "findings": [
    {
      "category": "Deserialization",
      "description": "User-controlled data passed to pickle.loads",
      "attack_vectors": ["upload endpoint accepts arbitrary .pkl files"],
      "priority": "critical",
      "evidence": "src/api/upload.py:42"
    }
  ],
  "context": { "profile": "<full LLM response - pass to next phase>" },
  "raw": "<full LLM response, untruncated>"
}
```

---

### `hd_audit` - Phase 2: Vulnerability Hunt

Systematically reasons through applicable vulnerability classes for each surface category found in Phase 1.

**What it covers:**
- OWASP Top 10 (2021): A01–A10
- SANS Top 25 CWEs: CWE-787, CWE-79, CWE-89, CWE-416, CWE-78, CWE-22, CWE-362, and more
- OWASP LLM Top 10: LLM01–LLM10 (prompt injection, insecure output, tool abuse, excessive agency, model theft, etc.)

Findings are rated by exploitability: `confirmed`, `likely`, or `theoretical`.

**Input**
```json
{
  "agent": "./agent.yaml",
  "target": "https://github.com/example/repo",
  "context": { "profile": "<Phase 1 output.context.profile>" }
}
```

**Output**
```json
{
  "phase": "audit",
  "status": "complete",
  "findings": [
    {
      "id": "AUDIT-001",
      "title": "Arbitrary code execution via pickle deserialization",
      "surface_category": "Deserialization",
      "vulnerability_class": "CWE-502",
      "cwe_id": "CWE-502",
      "affected_component": "src/api/upload.py:42",
      "attack_scenario": "Attacker uploads a crafted .pkl file → server deserializes it → arbitrary OS command executed",
      "exploitability": "confirmed",
      "severity_estimate": "critical",
      "evidence": "open(request.files['data'], 'rb') passed directly to pickle.loads()",
      "requires_poc": true
    }
  ],
  "context": { "profile": "...", "audit": "<full LLM response>" },
  "raw": "<full LLM response>"
}
```

---

### `hd_confirm` - Phase 3: PoC Generation

Writes a minimal, self-contained, deterministic Proof of Concept for a specific audit finding.

**PoC output structure:**
- Prerequisites and required access level
- `Requires Live Environment: YES / NO`
- Root cause (one paragraph - the exact code path, missing check, invariant violated)
- Numbered copy-paste steps
- Complete runnable PoC code block
- Expected output (exploited vs. patched)
- Impact demonstration
- Limitations and conditions

**Input**
```json
{
  "agent": "./agent.yaml",
  "target": "https://github.com/example/repo",
  "context": {
    "profile": "...",
    "audit": "<Phase 2 output.context.audit>"
  }
}
```

**Output**
```json
{
  "phase": "confirm",
  "status": "complete",
  "findings": [
    {
      "poc": "## Vulnerability Reference\nAUDIT-001 - Arbitrary code execution...\n\n## PoC Code\n```python\nimport pickle, requests\n...\n```"
    }
  ],
  "context": { "profile": "...", "audit": "...", "confirm": "<full LLM response>" },
  "raw": "<full LLM response>"
}
```

---

### `hd_assess` - Phase 4: CVSS v3.1 + CWE Scoring

Scores the vulnerability using chain-of-thought reasoning through each CVSS v3.1 metric before committing to a numeric score. Never hallucinates - reasons through AV, AC, PR, UI, S, C, I, A individually.

**CVSS metrics reasoned through:**

| Metric | Options | Key question |
| --- | --- | --- |
| Attack Vector (AV) | N / A / L / P | How far can the attacker be? |
| Attack Complexity (AC) | L / H | Are special conditions required? |
| Privileges Required (PR) | N / L / H | What account level does the attacker need? |
| User Interaction (UI) | N / R | Does a victim need to act? |
| Scope (S) | U / C | Does impact cross component boundaries? |
| Confidentiality (C) | N / L / H | How much data is exposed? |
| Integrity (I) | N / L / H | Can data be modified? |
| Availability (A) | N / L / H | Can the system be disrupted? |

**Input**
```json
{
  "agent": "./agent.yaml",
  "target": "https://github.com/example/repo",
  "context": {
    "audit": "...",
    "confirm": "<Phase 3 output.context.confirm>"
  }
}
```

**Output**
```json
{
  "phase": "assess",
  "status": "complete",
  "findings": [
    {
      "vulnerability_id": "AUDIT-001",
      "title": "Arbitrary code execution via pickle deserialization",
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "cvss_score": 9.8,
      "severity": "Critical",
      "cwe_id": "CWE-502",
      "cwe_name": "Deserialization of Untrusted Data",
      "exploitability_subscore": 3.9,
      "impact_subscore": 5.9,
      "epss_estimate": "high",
      "patch_complexity": "moderate",
      "notes": "No authentication required - upload endpoint is public"
    }
  ],
  "context": { "...", "assess": "<full LLM response>" },
  "raw": "<full LLM response with CoT reasoning>"
}
```

---

### `hd_draft_ghsa` - Phase 5: GHSA Draft

Produces a GitHub Security Advisory draft following the GitHub Advisory Database schema exactly.

**Schema fields produced:**
`ghsa_id` (PENDING) · `severity` · `summary` (≤100 chars) · `details` (full markdown) · `affected` (package + version ranges) · `references` · `published: null` · `withdrawn: null` · `aliases: []` · `database_specific` (cwes, cvss vector + score)

**Input**
```json
{
  "agent": "./agent.yaml",
  "target": "https://github.com/example/repo",
  "context": {
    "audit": "...",
    "confirm": "...",
    "assess": "<Phase 4 output.context.assess>"
  }
}
```

**Output**
```json
{
  "phase": "draft_ghsa",
  "status": "complete",
  "findings": [
    {
      "ghsa_draft": "## Disclosure Rationale\nNotify maintainer first...\n\n## GHSA Draft\n```yaml\nghsa_id: PENDING\nseverity: CRITICAL\nsummary: \"RCE via pickle deserialization in upload endpoint\"\n...\n```"
    }
  ],
  "context": { "...", "draft_ghsa": "<full LLM response>" },
  "raw": "<full LLM response>"
}
```

---

### `hd_disclose` - Phase 6: Coordinated Disclosure Package

Produces three distinct documents in a single LLM call, each calibrated for a different audience.

| Output | Audience | Content |
| --- | --- | --- |
| Executive Brief | CISO, VP Eng, Board | 2 paragraphs, no CVE IDs or CVSS vectors - business impact + recommended response |
| Technical Advisory | Security engineers, devs, IR | Root cause, affected versions, CVSS, CWE, attack scenario, detection IoCs, remediation steps, timeline |
| Vendor Email Template | Vendor's security team | Professional tone, summary, CVSS vector, 90-day disclosure timeline, PoC offer under embargo |

**Input**
```json
{
  "agent": "./agent.yaml",
  "target": "https://github.com/example/repo",
  "context": {
    "audit": "...",
    "confirm": "...",
    "assess": "...",
    "draft_ghsa": "<Phase 5 output.context.draft_ghsa>"
  }
}
```

**Output**
```json
{
  "phase": "disclose",
  "status": "complete",
  "findings": [
    { "type": "executive_brief", "content": "A critical vulnerability was identified..." },
    { "type": "technical_advisory", "content": "## Vulnerability\nCVSS 9.8 Critical..." },
    { "type": "vendor_email_template", "content": "Subject: [Security Disclosure] RCE in upload.py..." }
  ],
  "context": { "...", "disclose": "<full LLM response>" },
  "raw": "<full LLM response>"
}
```

---

### `hd_run` - Full Pipeline (all 6 phases)

Runs phases 1–6 sequentially. Context is chained automatically - no manual wiring needed.

**Input**
```json
{
  "agent": "./agent.yaml",
  "target": "https://github.com/example/target-repo"
}
```

**Output**
```json
{
  "session_file": ".hyperdope/sessions/2026-08-24T12-00-00-000Z.json",
  "phases_completed": ["profile", "audit", "confirm", "assess", "draft_ghsa", "disclose"],
  "final_context": {
    "profile": "...",
    "audit": "...",
    "confirm": "...",
    "assess": "...",
    "draft_ghsa": "...",
    "disclose": "..."
  },
  "results": {
    "profile": { "phase": "profile", "status": "complete", "findings": [...] },
    "audit":   { "phase": "audit",   "status": "complete", "findings": [...] },
    "confirm": { "..." },
    "assess":  { "..." },
    "draft_ghsa": { "..." },
    "disclose":   { "..." }
  }
}
```

---

<a id="session-resume"></a>
## Session Resume

Every `hd_run` execution writes a session file to `.hyperdope/sessions/{timestamp}.json`. The file is append-safe - resuming never overwrites completed phases.

**To resume from any phase:**

1. Open the session file:
```bash
cat .hyperdope/sessions/2026-08-24T12-00-00-000Z.json
```

2. Copy the `context` object from the last completed phase's result.

3. Call the next phase tool with that context:
```json
{
  "tool": "hd_assess",
  "arguments": {
    "agent": "./agent.yaml",
    "target": "https://github.com/example/repo",
    "context": {
      "profile": "<from session file>",
      "audit":   "<from session file>",
      "confirm": "<from session file>"
    }
  }
}
```

Individual phase tool calls (`hd_audit`, `hd_confirm`, etc.) also write their results to the session file when a `context` argument is passed in.

---

<a id="providers"></a>
## Providers

| `provider` value | SDK | Notes |
| --- | --- | --- |
| `claude` | `@anthropic-ai/sdk` | Anthropic Claude (Sonnet, Opus, Haiku) |
| `openai` | `openai` | GPT-4o, GPT-4 Turbo, o1, etc. |
| `gemini` | `@google/generative-ai` | Gemini 1.5 Pro, Flash, 2.0 |
| `ollama` | `fetch` | Local models via Ollama at localhost:11434 |
| `glm` | `openai` + `base_url` | Zhipu GLM-4, openai-compatible |
| `kimi` | `openai` + `base_url` | Moonshot Kimi, openai-compatible |
| `qwen` | `openai` + `base_url` | Alibaba Qwen, openai-compatible |

Any OpenAI-compatible endpoint works with `provider: openai` + `base_url` pointing to the API.

**Provider config examples:**

```yaml
# OpenAI
provider: openai
model: gpt-4o
api_key: ${OPENAI_API_KEY}

# Gemini
provider: gemini
model: gemini-1.5-pro
api_key: ${GEMINI_API_KEY}

# Ollama (local - no api_key needed)
provider: ollama
model: llama3.1:70b
base_url: http://localhost:11434

# GLM (openai-compatible)
provider: glm
model: glm-4-plus
api_key: ${GLM_API_KEY}
base_url: https://open.bigmodel.cn/api/paas/v4

# Kimi (openai-compatible)
provider: kimi
model: moonshot-v1-128k
api_key: ${MOONSHOT_API_KEY}
base_url: https://api.moonshot.cn/v1

# Qwen (openai-compatible)
provider: qwen
model: qwen-max
api_key: ${DASHSCOPE_API_KEY}
base_url: https://dashscope.aliyuncs.com/compatible-mode/v1
```

---

<a id="troubleshooting"></a>
## Troubleshooting

| Problem | Fix |
| --- | --- |
| `Cannot read agent config: ...` | Check the path in `--agent` or `HYPERDOPE_AGENT`. File must exist and be valid YAML. |
| `Missing required environment variable: CLAUDE_API_KEY` | Export the variable before starting the host: `export CLAUDE_API_KEY=sk-ant-...` or add it to the MCP host's `env` block. |
| `Unknown provider: "..."` | Check `provider:` in agent.yaml - valid values: `claude`, `openai`, `gemini`, `ollama`, `glm`, `kimi`, `qwen`. |
| Tool returns `"status": "partial"` | The LLM response didn't produce parseable JSON. The full response is still in `raw`. Check the model's output or lower `temperature`. |
| MCP host doesn't see the tools | Restart the host after editing `.mcp.json`. Verify `node --version` ≥ 20. |
| Ollama connection refused | Start Ollama: `ollama serve`. Confirm the model is pulled: `ollama pull llama3.1:70b`. |
| Rate limit / 429 errors | Add `temperature` and `max_tokens` guards in agent.yaml, or switch to a provider with higher limits. |
| Session file not created | `hd_run` writes to `.hyperdope/sessions/` relative to the cwd where the MCP host launched the server. Check launch directory. |

---

<a id="disclaimer"></a>
## Disclaimer

Hyperdope is for **authorized** security research, penetration testing, vulnerability disclosure programs, and CTF competitions only. You must have explicit written authorization before targeting any system you do not own.

The built-in prompts are designed for adversarial research. PoC output from `hd_confirm` should be handled as sensitive material. Advisory drafts from `hd_draft_ghsa` and `hd_disclose` should follow responsible disclosure practices - notify the vendor before public release.

The authors assume no liability for misuse.

---

## License

MIT
