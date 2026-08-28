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

### Security
- `src/internal/config-loader.js`: path traversal + prototype pollution guard (HD-CVE-2026-0052)
- `src/internal/vault-bridge.js`: SSRF + TLS bypass restriction (HD-CVE-2026-0049)
- `src/internal/auth-bridge.js`: JWT skipExpiry replaced with private Symbol (HD-CVE-2026-0047)
- `src/internal/token-vault.js`: MWK zeroed after keyring init (HD-CVE-2026-0050)
- `src/internal/session-manager.js`: refresh token rotation on every use (HD-CVE-2026-0051)
- `src/internal/crypto-primitives.js`: timing oracle fix in safeCompare (HD-CVE-2026-0053)
- `src/phases/scan.js`: CWD boundary check on target parameter + lockfile size limit
- `src/providers/claude.js`: API key scrubbing in error messages
- `src/providers/openai.js`: API key scrubbing in error messages
- `src/providers/gemini.js`: API key scrubbing in error messages

### Added
- `smithery.yaml` for Smithery registry discovery
- `CHANGELOG.md` (this file)
- `CONTRIBUTING.md` developer onboarding guide
- MCP `instructions` field in server capabilities
- Structured error wrapping (`isError: true`) in all tool handlers
- Atomic session file writes using rename pattern
- `.github/ISSUE_TEMPLATE/` bug report + feature request templates
- `hd_verify` and `hd_scan` documentation in README
- `hd_verify` added to CI tool registration check
- `exports` map in package.json for programmatic API use

### Changed
- Session file writes now use atomic temp-file-then-rename pattern

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
