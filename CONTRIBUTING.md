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

Node.js >= 20 required.

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
