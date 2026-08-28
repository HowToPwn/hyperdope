# AGENT STRUCTURE PROMPT — HowToPwn/hyperdope
# Nâng cấp project lên tiêu chuẩn MCP production-grade

## Mục tiêu

Hyperdope hiện có core logic tốt nhưng thiếu các tiêu chuẩn cần thiết để cạnh tranh với các MCP top-tier (filesystem-mcp, github-mcp, sequential-thinking, playwright-mcp). Prompt này hướng dẫn agent bổ sung **infrastructure, discoverability, developer UX** mà không động vào phase logic.

---

## PHẦN 1 — `package.json`: Exports Map + Package Metadata

**Vấn đề:**  
Không có `"exports"` field → consumers không thể import programmatic API. Không có `"main"` → Node CJS fallback undefined. Không có `"types"` → TypeScript users bị mù.

**Fix:**

```json
{
  "main": "./src/server.js",
  "exports": {
    ".": {
      "import": "./src/server.js",
      "default": "./src/server.js"
    },
    "./schema": "./src/schema.js",
    "./cvss": "./src/cvss.js",
    "./config": "./src/config.js",
    "./session": "./src/session.js",
    "./providers": "./src/providers/index.js"
  },
  "repository": {
    "type": "git",
    "url": "git+https://github.com/HowToPwn/hyperdope.git"
  }
}
```

Không thêm TypeScript (giữ JS thuần), nhưng thêm `"exports"` để programmatic use và MCP registry discovery hoạt động đúng.

---

## PHẦN 2 — `smithery.yaml`: Smithery Registry Discovery

**Vấn đề:**  
Không có `smithery.yaml` → không xuất hiện trên [smithery.ai](https://smithery.ai) — registry phổ biến nhất cho MCP. Các MCP lớn như `github-mcp`, `playwright-mcp`, `sequential-thinking` đều có file này.

**Tạo file: `smithery.yaml`** (root of repo)

```yaml
name: hyperdope
displayName: Hyperdope — Adversarial Security Research Pipeline
description: |
  6-phase agentic security pipeline: attack surface profiling, vulnerability
  hunting, PoC generation, CVSS v3.1 scoring, GHSA drafting, and coordinated
  disclosure. Also includes Phase 0 dependency scan (OSV.dev) and patch
  verification. Supports Claude, GPT-4o, Gemini, Ollama, and any
  OpenAI-compatible provider.
version: "0.3.1"
license: MIT
homepage: https://github.com/HowToPwn/hyperdope
repository: https://github.com/HowToPwn/hyperdope
author:
  name: HowToPwn
  url: https://github.com/HowToPwn
categories:
  - security
  - code-analysis
  - devtools
tags:
  - security-research
  - vulnerability-scanner
  - cvss
  - ghsa
  - osv
  - disclosure
  - pentest
  - code-audit
  - sarif
  - sbom
icon: 🔮
startCommand:
  type: stdio
  command: npx
  args: ["hyperdope"]
  env:
    CLAUDE_API_KEY:
      description: Anthropic API key (required if using provider=claude)
      required: false
    OPENAI_API_KEY:
      description: OpenAI API key (required if using provider=openai)
      required: false
    HYPERDOPE_AGENT:
      description: Path to agent.yaml config file (alternative to passing --agent per call)
      required: false
tools:
  - name: hd_scan
    description: Phase 0 — Dependency CVE scan, secret detection, supply-chain hooks, ghost endpoints. No LLM required.
  - name: hd_profile
    description: Phase 1 — STRIDE threat model, attack surface mapping, data flow tracing.
  - name: hd_audit
    description: Phase 2 — 5-step adversarial vulnerability hunt. OWASP Top 10 + LLM Top 10.
  - name: hd_confirm
    description: Phase 3 — Minimal deterministic PoC generation with reliability rating.
  - name: hd_assess
    description: Phase 4 — CVSS v3.1 scoring with chain-of-thought per metric. Mathematically verified.
  - name: hd_draft_ghsa
    description: Phase 5 — GitHub Security Advisory draft following GHSA schema exactly.
  - name: hd_disclose
    description: Phase 6 — Coordinated disclosure package. Executive brief + technical advisory + vendor email.
  - name: hd_verify
    description: Patch verification — PATCHED / STILL_VULNERABLE / PARTIAL_FIX / CANNOT_VERIFY verdict.
  - name: hd_run
    description: Full pipeline runner — all 6 phases sequentially with auto context chaining. Resumable.
```

---

## PHẦN 3 — `CHANGELOG.md`: Release History

**Vấn đề:**  
Không có CHANGELOG → npm users không biết gì thay đổi giữa các version. Mọi MCP có traction đều có file này. CI publish workflow đã tạo GitHub releases, nhưng không có CHANGELOG tương ứng.

**Tạo file: `CHANGELOG.md`** (root of repo)

```markdown
# Changelog

All notable changes to hyperdope are documented here.  
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.3.1] — 2026-08-28

### Fixed
- `src/providers/claude.js`: removed leftover `//dummy text` debug comment
- `README.md`: corrected clone URL (`your-org` → `HowToPwn`)

---

## [0.3.0] — 2026-08-24

### Added
- `hd_verify` tool — patch verification phase (PATCHED / STILL_VULNERABLE / PARTIAL_FIX / CANNOT_VERIFY)
- `hd_scan` tool — Phase 0 dependency scan, now exported as standalone MCP tool
- Ghost endpoint discovery via `git log -p` diff analysis
- Blast radius enrichment (npm + PyPI download counts)
- Dependency confusion detection for npm unscoped packages
- SBOM-lite generation (hyperdope-sbom-lite-1.0 format)
- `resume_from` + `session_file` support in `hd_run` — resume pipeline from any completed phase
- SARIF 2.1.0 export via `hd-ci` CLI for GitHub Code Scanning integration
- `HyperFindingSchema` (Zod) — canonical normalized finding contract across all phases
- `computeConfidence()` — evidence-quality confidence scoring (1–5), programmatic, anti-hallucination
- `wrapDataBlock()` in context.js — `<pipeline_data>` boundary tags for prompt injection mitigation
- Brand TUI system in `tui.js` (Hyperdope AI color palette, spinner, severity badges, confidence badges)
- `hd_scan` ghost endpoint, postinstall hook, and secret detection findings

### Changed
- Phase system prompts updated to OWASP LLM Top 10 (2025 edition) — LLM01–LLM10
- Context trimming now uses `<pipeline_data>` wrapper to signal data vs instruction to LLM
- Session files written with `mode: 0o600`, session directory with `mode: 0o700`
- `withRetry()` now skips retry on network/connection errors to prevent SSRF probe amplification

### Security
- `base_url` SSRF guard in `src/providers/index.js` — blocks IMDS, private RFC 1918 ranges, IPv4-mapped IPv6
- `validateSessionPath()` in `server.js` — symlink + path traversal containment on `session_file` parameter
- `resolveObj()` in `config.js` — strips `__proto__`, `constructor`, `prototype` from agent YAML keys
- `O_NOFOLLOW` flag on all file opens in `detectSecrets()` — closes symlink TOCTOU window
- `safeCompare()` uses `timingSafeEqual` — no secret-material string comparison

---

## [0.2.0] — 2026-07-15

### Added
- Multi-provider support: OpenAI, Gemini, Ollama, GLM, Kimi, Qwen
- `withRetry()` with exponential backoff — 3 attempts, 1s base delay
- `extractJson()` / `extractJsonArray()` — O(n) balanced-brace extraction, no regex backtracking
- `calculateScore()` — CVSS v3.1 base score calculator (mathematical, not LLM-derived)
- `hd-ci` CLI — SARIF export, severity threshold gate, `--json` mode for CI pipelines
- `hd-run` CLI — standalone pipeline runner without MCP host requirement
- Agent YAML `phases.*` overrides — per-phase system prompt and user prefix customization
- `trimContext()` — token budget enforcement with phase-priority trimming order

### Changed
- All phases now emit `normalized_findings` array alongside raw `findings`
- Session files stored in `.hyperdope/sessions/` with ISO timestamp filenames

---

## [0.1.0] — 2026-06-01

### Added
- Initial 6-phase MCP pipeline: profile → audit → confirm → assess → draft_ghsa → disclose
- Claude provider (Anthropic SDK)
- `agent.yaml` config with `${VAR}` env resolution
- Session persistence — phase results written to `.hyperdope-session.json`
- GHSA schema draft output (Phase 5)
- Coordinated disclosure package — executive brief + technical advisory + vendor email (Phase 6)
```

---

## PHẦN 4 — `CONTRIBUTING.md`: Developer Onboarding

**Vấn đề:**  
Không có CONTRIBUTING.md → open-source contributors không biết cách setup, test, hay submit PR. Ảnh hưởng trực tiếp đến GitHub community health score (hiện đang thiếu badge này).

**Tạo file: `CONTRIBUTING.md`** (root of repo)

```markdown
# Contributing to Hyperdope

Thank you for your interest. This document covers how to set up a development
environment, run tests, and submit changes.

---

## Quick Setup

```bash
git clone https://github.com/HowToPwn/hyperdope.git
cd hyperdope
npm install
npm test
```

Node.js ≥ 20 required.

---

## Project Layout

```
bin/          CLI entrypoints (hyperdope, hd-run, hd-ci)
src/
  server.js   MCP server — tool registration
  config.js   Agent YAML loader + path validation
  session.js  Session persistence
  context.js  Context trimming + pipeline_data wrapping
  schema.js   HyperFindingSchema (Zod) + SARIF export
  cvss.js     CVSS v3.1 calculator (mathematical)
  extract.js  O(n) JSON extraction from LLM output
  retry.js    Exponential backoff retry
  tui.js      Terminal UI (colors, badges, spinner)
  ci.js       hd-ci pipeline logic
  phases/     One file per pipeline phase (profile, audit, confirm, assess, draft_ghsa, disclose, scan, verify)
  providers/  LLM provider adapters (claude, openai, gemini, ollama)
  internal/   Internal auth stack (not used by MCP tools — see src/internal/README.internal.md)
test/
  cvss.test.js
  extract.test.js
  retry.test.js
  security_containment.test.js
```

---

## Running Tests

```bash
npm test                  # all tests
node --test test/cvss.test.js   # single file
```

Tests use Node.js built-in `node:test` — no extra test runner needed.

---

## Adding or Modifying a Phase

1. Edit the relevant file in `src/phases/`. Each phase exports a `runXxx` function and a `BUILT_IN` object containing the default system prompt and user prefix.
2. If you add a new phase, register it in `src/phases/index.js` and `src/server.js`.
3. Add a `normalizeFinding()` case in `src/schema.js` for the new phase.
4. Document the new tool in `README.md` (Tools section) and `smithery.yaml` (tools list).

---

## Adding a Provider

1. Create `src/providers/<name>.js` exporting `async function complete({ system, user, model, api_key, base_url, max_tokens, temperature })`.
2. Register the provider in `src/providers/index.js` (add to `OPENAI_COMPAT` set or add a new branch).
3. Add a config example to `agent.example.yaml`.
4. Document in the Providers table in `README.md`.

---

## Code Style

- ESM only (`"type": "module"` in `package.json`)
- No TypeScript, no build step — plain JS with JSDoc
- All output to stderr (stdout reserved for structured JSON/SARIF)
- Respect `NO_COLOR` and `TERM=dumb` conventions in any TTY output
- Every file that touches security-sensitive paths must have a comment citing the CWE and explaining the mitigation

---

## Pull Request Checklist

- [ ] `npm test` passes
- [ ] `node --check` passes on all modified files
- [ ] `npm pack --dry-run` shows no unexpected files
- [ ] New tools documented in `README.md` and `smithery.yaml`
- [ ] CHANGELOG.md updated under `[Unreleased]`
- [ ] No secrets, tokens, or internal paths in committed files

---

## Security Issues

Do **not** open a public issue for security vulnerabilities. See [SECURITY.md](./SECURITY.md).
```

---

## PHẦN 5 — README.md: Bổ sung `hd_verify` + `hd_scan` vào Tools section

**Vấn đề:**  
`hd_verify` và phase 0 (`hd_scan`) đều có trong `server.js` nhưng **không được document trong README**. Người dùng npm hoàn toàn không biết chúng tồn tại.

**Tìm section `## Tools` trong README.md và thêm vào cuối (trước `hd_run`):**

```markdown
### `hd_scan` — Phase 0: Dependency & Supply-Chain Scan

Scans a local directory against the [OSV.dev](https://osv.dev) CVE database.
No API key or agent config required — runs entirely local + public APIs.

**What it covers:** npm (package-lock.json / package.json), Python
(requirements.txt / poetry.lock / Pipfile.lock), Go (go.mod), Rust (Cargo.lock),
hardcoded secrets (AWS keys, GitHub PATs, Anthropic/OpenAI keys, PEM blocks),
npm lifecycle hooks (postinstall / preinstall), dependency confusion suspects,
ghost endpoints (removed routes still in git history), SBOM-lite generation.

**Input**
```json
{
  "target": "./",
  "context": {}
}
```

**Output** — `findings[]` contains OSV CVEs, secrets, hooks, ghost endpoints, confusion suspects.
`meta` contains package counts, ecosystem list, and SBOM. `sbom` contains the full SBOM-lite object.

---

### `hd_verify` — Patch Verification Phase

Determines whether previously reported vulnerabilities are actually fixed in a
patched version. Uses a 4-question methodology:

1. Root cause identification — what exact code path caused the original finding?
2. Change analysis — does the patch close that exact path, or only a symptom?
3. Variant bypass check — are there alternative inputs that bypass the fix?
4. Sibling site audit — are there other locations in the codebase with the same pattern?

**Verdict:** `PATCHED` · `STILL_VULNERABLE` · `PARTIAL_FIX` · `CANNOT_VERIFY`

Run after `hd_assess` (or `hd_confirm`) when a patch is available.

**Input**
```json
{
  "agent": "./agent.yaml",
  "target": "https://github.com/example/repo/commit/abc123",
  "context": {
    "audit": "<Phase 2 context>",
    "confirm": "<Phase 3 context>",
    "assess": "<Phase 4 context>"
  }
}
```
```

---

## PHẦN 6 — `src/server.js`: MCP `serverInfo` + `instructions` field

**Vấn đề:**  
MCP protocol hỗ trợ `instructions` field trong server capabilities — đây là nơi MCP clients (Claude Desktop, Cursor) hiển thị "how to use this server" prompt. Hiện tại server không set field này → clients không có context.

**Trong `createServer()` ở `src/server.js`, sửa McpServer constructor:**

```js
export function createServer() {
  const server = new McpServer({
    name:    'hyperdope',
    version: '0.3.1',        // bump khi release
    instructions: `Hyperdope is a 6-phase adversarial security research pipeline.

WORKFLOW:
1. hd_scan   — Scan dependencies, secrets, hooks (no API key needed). Run this first on any local target.
2. hd_profile — Map the attack surface (STRIDE, data flows, trust boundaries).
3. hd_audit  — Hunt vulnerabilities (OWASP Top 10, SANS 25, LLM Top 10).
4. hd_confirm — Generate PoCs with reliability ratings.
5. hd_assess — Score with CVSS v3.1 (mathematically verified, not LLM-guessed).
6. hd_draft_ghsa — Draft a GitHub Security Advisory.
7. hd_disclose — Generate executive brief + technical advisory + vendor email.

Use hd_run to execute all 6 LLM phases automatically with context chaining.
Use hd_verify after a patch is available to confirm the fix.

SETUP: An agent.yaml config file specifying provider and API key is required for
all LLM phases (hd_profile through hd_disclose, hd_verify). hd_scan runs without it.

Example agent.yaml:
  provider: claude
  model: claude-sonnet-4-6
  api_key: \${CLAUDE_API_KEY}`,
  });
  // ... rest unchanged
```

---

## PHẦN 7 — `src/server.js`: Tool Error Wrapping Chuẩn Hóa

**Vấn đề:**  
`makePhaseHandler()` không catch errors từ `runFn()`. Nếu provider throws (rate limit, bad API key, network), MCP client nhận unhandled exception → connection reset thay vì structured error response. Đây là failure mode phổ biến nhất mà users báo cáo với MCP servers.

**Sửa `makePhaseHandler()` trong `src/server.js`:**

```js
function makePhaseHandler(phaseName, runFn) {
  return async ({ agent, target, context }) => {
    let config;
    try {
      config = loadAgentConfig(agent);
    } catch (err) {
      return {
        content: [{ type: 'text', text: JSON.stringify({
          phase:  phaseName,
          status: 'error',
          error:  err.message,
          hint:   'Check that agent.yaml exists and contains valid provider/model/api_key fields.',
        }, null, 2) }],
        isError: true,    // MCP protocol field — signals tool error to client
      };
    }

    const phaseConfig = config.phases?.[phaseName] ?? null;
    const trimmed = trimContext(context ?? {}, phaseName);

    let result;
    try {
      result = await runFn({ config, target, context: trimmed, callProvider, phaseConfig });
    } catch (err) {
      return {
        content: [{ type: 'text', text: JSON.stringify({
          phase:  phaseName,
          status: 'error',
          error:  err.message,
          // Scrub API keys from error messages before returning
          ...(err.stack ? { stack: err.stack.replace(/sk-[A-Za-z0-9-]{20,}/g, 'sk-[REDACTED]') } : {}),
        }, null, 2) }],
        isError: true,
      };
    }

    const sf = sessionPath(newSessionTimestamp());
    writePhaseToSession(sf, phaseName, result);

    return {
      content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
    };
  };
}
```

Apply the same try/catch pattern to the `hd_run`, `hd_scan`, and `hd_verify` handlers — each currently throws unhandled on config/provider errors.

---

## PHẦN 8 — `src/session.js`: Session Directory Race Condition

**Vấn đề:**  
`writePhaseToSession()` calls `mkdirSync` then `readSession()` then `writeFileSync` — không atomic. Nếu hai tool calls chạy concurrent (MCP clients có thể invoke tools in parallel), race condition gây corrupt session JSON.

**Sửa `writePhaseToSession()` trong `src/session.js`:**

```js
import { mkdirSync, readFileSync, writeFileSync, existsSync, renameSync } from 'fs';
import { resolve, join, dirname } from 'path';
import { randomBytes } from 'node:crypto';

export function writePhaseToSession(filePath, phaseName, result) {
  mkdirSync(SESSIONS_DIR, { recursive: true, mode: 0o700 });

  // Atomic write: write to a temp file, then rename (rename is atomic on POSIX)
  const tmp = filePath + '.tmp.' + randomBytes(4).toString('hex');

  const existing = readSession(filePath);
  existing[phaseName] = result;
  existing._updated = new Date().toISOString();

  try {
    writeFileSync(tmp, JSON.stringify(existing, null, 2), { encoding: 'utf8', mode: 0o600 });
    renameSync(tmp, filePath);
  } catch (err) {
    // Clean up temp file on failure
    try { if (existsSync(tmp)) require('fs').unlinkSync(tmp); } catch {}
    throw err;
  }
}
```

Import `renameSync` và `randomBytes`. Sử dụng ESM-compatible import thay vì `require`.

---

## PHẦN 9 — `.github/workflows/ci.yml`: Thêm `hd_verify` vào tool registration check

**Vấn đề:**  
CI check hiện verify `['hd_scan','hd_profile','hd_audit','hd_confirm','hd_assess','hd_draft_ghsa','hd_disclose','hd_run']` — thiếu `hd_verify`. Nếu ai refactor quên export nó, CI pass.

**Sửa cả `ci.yml` và `publish.yml`, trong step "Verify all tools register":**

```bash
const expected = [
  'hd_scan','hd_profile','hd_audit','hd_confirm',
  'hd_assess','hd_draft_ghsa','hd_disclose',
  'hd_verify','hd_run'
];
```

---

## PHẦN 10 — `src/phases/scan.js`: Size Limit cho JSON Parsing

**Vấn đề:**  
Lockfile parsers dùng `readFileSync` + `JSON.parse` không có size limit. Một `package-lock.json` malicious 500MB sẽ OOM cả process. Real-world MCP servers cần guard này.

**Thêm helper vào đầu `src/phases/scan.js`:**

```js
import { readFileSync, statSync } from 'fs';

const MAX_LOCKFILE_BYTES = 20 * 1024 * 1024; // 20 MB

function safeReadJson(filePath) {
  try {
    const { size } = statSync(filePath);
    if (size > MAX_LOCKFILE_BYTES) {
      process.stderr.write(
        `[hd_scan] Skipping ${filePath} — size ${(size / 1024 / 1024).toFixed(1)} MB exceeds ${MAX_LOCKFILE_BYTES / 1024 / 1024} MB limit\n`
      );
      return null;
    }
    return JSON.parse(readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}
```

Thay thế tất cả `JSON.parse(readFileSync(lockPath, 'utf8'))` trong scan.js bằng `safeReadJson(lockPath)` và handle `null` return.

---

## PHẦN 11 — `.github/ISSUE_TEMPLATE/`: Issue Templates

**Vấn đề:**  
Không có issue templates → users submit bug reports thiếu thông tin, maintainer tốn thời gian follow-up. Top MCPs đều có bug report + feature request templates.

**Tạo thư mục `.github/ISSUE_TEMPLATE/` với 2 files:**

**`.github/ISSUE_TEMPLATE/bug_report.yml`:**
```yaml
name: Bug Report
description: Report a reproducible bug in hyperdope
labels: ["bug", "needs-triage"]
body:
  - type: markdown
    attributes:
      value: |
        **Security vulnerabilities:** use [SECURITY.md](../SECURITY.md), not this form.
  - type: input
    id: version
    attributes:
      label: Hyperdope version
      description: Output of `npm list hyperdope` or `npx hyperdope --version`
    validations:
      required: true
  - type: input
    id: node
    attributes:
      label: Node.js version
      description: Output of `node --version`
    validations:
      required: true
  - type: dropdown
    id: provider
    attributes:
      label: LLM provider
      options: [claude, openai, gemini, ollama, glm, kimi, qwen, other]
    validations:
      required: true
  - type: textarea
    id: description
    attributes:
      label: What happened?
      description: Include the tool name (hd_scan, hd_audit, etc.) and the exact error or incorrect output.
    validations:
      required: true
  - type: textarea
    id: reproduce
    attributes:
      label: Steps to reproduce
      description: Minimal agent.yaml (no real API keys), tool call arguments, and the command you ran.
    validations:
      required: true
  - type: textarea
    id: expected
    attributes:
      label: Expected behavior
    validations:
      required: true
```

**`.github/ISSUE_TEMPLATE/feature_request.yml`:**
```yaml
name: Feature Request
description: Suggest an improvement to the pipeline or tooling
labels: ["enhancement"]
body:
  - type: textarea
    id: problem
    attributes:
      label: What problem does this solve?
      description: Describe the gap in the current pipeline or UX friction you're experiencing.
    validations:
      required: true
  - type: textarea
    id: solution
    attributes:
      label: Proposed solution
      description: What would you like to see added or changed?
    validations:
      required: true
  - type: dropdown
    id: area
    attributes:
      label: Area
      options:
        - Phase logic (profile/audit/confirm/assess/draft_ghsa/disclose/verify)
        - hd_scan (dependency/secret/supply-chain scanning)
        - Provider support
        - CLI (hd-run / hd-ci)
        - MCP protocol / server
        - Documentation
        - CI/CD integration
        - Other
    validations:
      required: true
```

---

## PHẦN 12 — `src/providers/claude.js`: Dọn API key leak khỏi error

**Vấn đề:**  
Nếu Anthropic SDK throw error với message chứa API key (truncated auth header), error được propagate thẳng tới MCP client response. Cần sanitize trước khi return.

**Sửa `src/providers/claude.js`:**

```js
import Anthropic from '@anthropic-ai/sdk';

const API_KEY_RE = /sk-ant-[A-Za-z0-9_-]{20,}/g;

function scrubApiKey(msg) {
  return typeof msg === 'string' ? msg.replace(API_KEY_RE, 'sk-ant-[REDACTED]') : msg;
}

export async function complete({ system, user, model, api_key, max_tokens = 8192, temperature = 0.2 }) {
  const client = new Anthropic({ apiKey: api_key });

  try {
    const msg = await client.messages.create({
      model,
      max_tokens,
      temperature,
      system,
      messages: [{ role: 'user', content: user }],
    });
    return msg.content.map(b => (b.type === 'text' ? b.text : '')).join('');
  } catch (err) {
    err.message = scrubApiKey(err.message);
    throw err;
  }
}
```

Apply tương tự cho `src/providers/openai.js` (scrub `sk-[A-Za-z0-9]{48,}`) và `src/providers/gemini.js`.

---

## SUMMARY TABLE

| # | File(s) | Type | Impact |
|---|---------|------|--------|
| 1 | `package.json` | Exports map | Programmatic import + registry compatibility |
| 2 | `smithery.yaml` (NEW) | Registry discovery | Xuất hiện trên smithery.ai, tăng discoverability |
| 3 | `CHANGELOG.md` (NEW) | Release history | npm trust signal, contributor transparency |
| 4 | `CONTRIBUTING.md` (NEW) | Developer onboarding | GitHub community health score, OSS credibility |
| 5 | `README.md` | Docs gap | `hd_verify` và `hd_scan` visible to users |
| 6 | `src/server.js` | MCP `instructions` | Client-side "how to use" context |
| 7 | `src/server.js` | Error wrapping + `isError` | Graceful failure, no connection reset |
| 8 | `src/session.js` | Atomic write | Race condition safety on concurrent tool calls |
| 9 | `.github/workflows/*.yml` | CI fix | `hd_verify` included in registration check |
| 10 | `src/phases/scan.js` | Lockfile size limit | OOM protection on malicious targets |
| 11 | `.github/ISSUE_TEMPLATE/` (NEW) | Issue templates | Structured bug reports, maintainer efficiency |
| 12 | `src/providers/*.js` | API key scrubbing | Credential hygiene in error paths |

---

## CONSTRAINTS CHO AGENT

1. **Không động vào** `src/phases/{profile,audit,confirm,assess,draft_ghsa,disclose,verify}.js` — phase prompts không được sửa.
2. **Không thêm dependencies mới** — dùng Node.js built-ins và các packages đã có.
3. **Không convert sang TypeScript** — giữ plain ESM JavaScript.
4. **Thứ tự ưu tiên thực hiện:** 2 (smithery.yaml) → 7 (error wrapping) → 6 (instructions) → 3 (CHANGELOG) → còn lại.
5. Sau khi xong, chạy:
   ```bash
   npm test
   npm pack --dry-run   # verify smithery.yaml + CHANGELOG.md + CONTRIBUTING.md xuất hiện
   node --check src/server.js src/session.js src/phases/scan.js src/providers/claude.js
   ```
