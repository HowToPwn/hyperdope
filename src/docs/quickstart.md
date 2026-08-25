# Hyperdope - Quickstart

From zero to your first finding in 5 minutes.

---

## Prerequisites

| | |
|---|---|
| **Node.js** | ≥ 20 - verify with: `node --version` |
| **API key** | Anthropic, OpenAI, Google, or local Ollama |
| **MCP client** | Claude Desktop, Cursor, or any MCP client |

---

## Step 1 - Installation

```bash
# Install globally (enables npx hd-ci / hd-run anywhere)
npm install -g hyperdope

# Or run directly without installation:
npx hyperdope
```

---

## Step 2 - Create Agent Config

```bash
# Copy from template
cp agent.example.yaml agent.yaml
```

Edit `agent.yaml` - choose provider and specify model:

```yaml
# agent.yaml - Claude (recommended)
provider: claude
model:    claude-opus-4-5
api_key:  ${ANTHROPIC_API_KEY}    # loaded from env, do not hardcode
```

Set environment variable:

```bash
# Linux / macOS
export ANTHROPIC_API_KEY=sk-ant-api03-...

# Windows PowerShell
$env:ANTHROPIC_API_KEY = "sk-ant-api03-..."

# Windows CMD
set ANTHROPIC_API_KEY=sk-ant-api03-...
```

> **Security:** Add `agent.yaml` to `.gitignore` - this file may contain API keys.
> `hd_scan` will automatically flag if you accidentally hardcode keys into YAML.

See all providers and options at [concepts/agent-yaml.md](concepts/agent-yaml.md).

---

## Step 3 - Connect MCP Client

### Claude Desktop

Locate config file by OS:

| OS | Path |
|---|---|
| **macOS** | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| **Windows** | `%APPDATA%\Claude\claude_desktop_config.json` |
| **Linux** | `~/.config/Claude/claude_desktop_config.json` |

Add to file (create if it doesn't exist):

```json
{
  "mcpServers": {
    "hyperdope": {
      "command": "npx",
      "args":    ["hyperdope"],
      "env": {
        "ANTHROPIC_API_KEY": "sk-ant-api03-..."
      }
    }
  }
}
```

**Or** if installed globally:

```json
{
  "mcpServers": {
    "hyperdope": {
      "command": "hyperdope"
    }
  }
}
```

Then **restart Claude Desktop**. Go to Settings → Developer → MCP Servers, verify `hyperdope` shows Connected status.

### Cursor / VS Code

Add to `.cursor/mcp.json` or `.vscode/mcp.json`:

```json
{
  "servers": {
    "hyperdope": {
      "type":    "stdio",
      "command": "npx",
      "args":    ["hyperdope"],
      "env": {
        "ANTHROPIC_API_KEY": "sk-ant-api03-..."
      }
    }
  }
}
```

---

## Step 4 - First Scan (No LLM Required)

`hd_scan` queries OSV.dev directly - no API key needed, zero cost.

**Option 1 - Use CLI `hd-ci` (fastest):**

```bash
npx hd-ci --target /path/to/your/project
```

Sample output:

```
╔════════════════════════════════════════════════════════╗
║ ❯ Hyperdope  hd-ci                                     ║
╚════════════════════════════════════════════════════════╝

  Target      /path/to/your/project
  Threshold   HIGH

  ✓  Scan complete: 312 pkgs  ·  2 CVEs  ·  0 secrets

  [HIGH    ] 2 findings
    · lodash@4.17.20 - Prototype pollution
        npm:lodash@4.17.20
    · semver@5.7.1 - ReDoS
        npm:semver@5.7.1

  ╔════════════════════════════════════════════════╗
  ║  ✗  FAIL  2 finding(s) ≥ HIGH                 ║
  ╚════════════════════════════════════════════════╝
```

**Option 2 - Use MCP tool `hd_scan`** (inside Claude Desktop / Cursor):

```
Call tool hd_scan with target = "/path/to/your/project"
```

Returned JSON output includes:
- `findings[]` - CVEs, secrets, hooks
- `meta.packages_scanned` - number of scanned packages
- `sbom` - full dependency list

---

## Step 5 - Run Full Audit Pipeline

### Option 1 - Standalone CLI `hd-run` (recommended for getting started)

No MCP client required, run directly from terminal:

```bash
npx hd-run --agent agent.yaml --target https://github.com/org/repo
```

Realtime output:

```
╔════════════════════════════════════════════════════════╗
║ ❯ hd-run  ·  Full Pipeline                            ║
║   github.com/org/repo                                 ║
╚════════════════════════════════════════════════════════╝

  ✓  1/6  Profile      → 9 surface categories
  ✓  2/6  Audit        → 4 candidates
    · [HIGH] Path traversal in /api/download
    · [HIGH] SSRF via webhook URL parameter
  ⠹  3/6  Confirm      generating PoCs…
  ✓  3/6  Confirm      → 3 PoCs generated
  ✓  4/6  Assess       → max CVSS 8.7  (4 findings)
  ✓  5/6  Draft GHSA   → advisory drafted
  ✓  6/6  Disclose     → disclosure package ready

  Session   .hyperdope-session-20260825T141032.json
  ╔════════════════════════════════════════════════╗
  ║  ✓  PASS  6/6 phases complete                 ║
  ╚════════════════════════════════════════════════╝
```

Run a single phase:

```bash
# Run scan only
npx hd-run --agent agent.yaml --target ./ --phase scan

# Run audit only
npx hd-run --agent agent.yaml --target https://github.com/org/repo --phase audit
```

### Option 2 - Use MCP tool `hd_run` (inside Claude Desktop / Cursor)

```
Call tool hd_run with:
  agent  = "agent.yaml"
  target = "https://github.com/org/repo"
```

The pipeline executes sequentially: `profile → audit → confirm → assess → draft_ghsa → disclose`

Session file is saved automatically.

---

## Step 6 - Resume Interrupted Pipeline

If the pipeline stops midway (network error, out of tokens, etc.), resume from the interrupted phase:

```bash
# CLI
npx hd-run --agent agent.yaml \
  --target https://github.com/org/repo \
  --resume-from confirm \
  --session-file .hyperdope-session-20260825T141032.json
```

```json
// MCP tool hd_run
{
  "agent":        "agent.yaml",
  "target":       "https://github.com/org/repo",
  "resume_from":  "confirm",
  "session_file": ".hyperdope-session-20260825T141032.json"
}
```

Hyperdope reads completed phase contexts from the session file, skips them, and continues from `confirm`.

---

## Step 7 - Verify Patch After Vendor Fix

```bash
npx hd-run --agent agent.yaml \
  --target "v2.3.1 (commit abc1234)" \
  --phase verify
```

Or via MCP tool `hd_verify` with context from audit + confirm + assess.

Returns a verdict for each finding: `PATCHED` / `PARTIAL_FIX` / `STILL_VULNERABLE` / `CANNOT_VERIFY`.

---

## CI/CD Integration

```bash
# Fail build if there are CVEs of High severity or above
npx hd-ci --target ./ --sarif-out results.sarif.json
# exit 0 = PASS, exit 1 = FAIL
```

See full guide at [guides/ci-integration.md](guides/ci-integration.md).

---

## Troubleshooting

### "Cannot find module" or "command not found"

```bash
# Check Node.js version (must be ≥ 20)
node --version

# Reinstall
npm install -g hyperdope@latest
```

### "base_url must use HTTPS" or "blocked metadata host"

`base_url` in `agent.yaml` points to an internal address or uses HTTP. See [concepts/agent-yaml.md](concepts/agent-yaml.md#security) for blocked address rules.

### "Agent config path must be within the working directory"

```bash
# Use env var instead of relative path
export HYPERDOPE_AGENT=/absolute/path/to/agent.yaml
```

Or run from the exact directory containing `agent.yaml`.

### Tool does not appear in Claude Desktop

1. Verify valid JSON config: `cat ~/Library/Application\ Support/Claude/claude_desktop_config.json | python3 -m json.tool`
2. Verify `npx hyperdope` runs in terminal under the same user as Claude Desktop
3. Check MCP logs: Claude Desktop → Settings → Developer → Logs

### OSV API returns an error

```bash
# Test directly
curl -s https://api.osv.dev/v1/query -d '{"package":{"name":"lodash","ecosystem":"npm"},"version":"4.17.20"}' | head -c 200
```

If OSV is down, `hd_scan` still returns secret detection and hook analysis; CVE list will include `osv_error` in `meta`.

---

## Next Steps

| Document | Content |
|---|---|
| [concepts/pipeline.md](concepts/pipeline.md) | Understand the 6 phases, context flow, injection mitigation |
| [concepts/agent-yaml.md](concepts/agent-yaml.md) | Full config options, 4 supported providers |
| [guides/audit-nodejs.md](guides/audit-nodejs.md) | End-to-end Node.js project audit guide |
| [guides/ci-integration.md](guides/ci-integration.md) | GitHub Actions workflow, SARIF export, weekly scanning |
