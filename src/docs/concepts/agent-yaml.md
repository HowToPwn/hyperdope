# Agent YAML Reference

Every Hyperdope tool call accepts the `agent` parameter - the path to this YAML config file. The file defines the LLM provider, model, and optional per-phase overrides.

---

## Minimal Example

```yaml
provider: claude
model:    claude-opus-4-5
api_key:  ${ANTHROPIC_API_KEY}
```

---

## Full Reference

```yaml
# ── Provider ──────────────────────────────────────────────────────────────────
# Required. One of: claude | openai | gemini | ollama
provider: claude

# ── Model ────────────────────────────────────────────────────────────────────
# Required. Model ID for the selected provider.
model: claude-opus-4-5

# ── API key ──────────────────────────────────────────────────────────────────
# Use ${ENV_VAR} syntax to read from environment - do not hardcode in file.
# You can omit this field if you have set the standard provider env var (see table below).
api_key: ${ANTHROPIC_API_KEY}

# ── Base URL (optional) ───────────────────────────────────────────────────────
# Override API endpoint. Used for:
#   - Azure OpenAI:               https://your-resource.openai.azure.com
#   - OpenAI-compatible proxy:    http://localhost:8080
#   - Ollama (default):           http://localhost:11434
#
# Security: base_url is validated on call - HTTPS only (or HTTP for localhost),
# RFC1918 addresses and IMDS metadata hosts are blocked.
base_url: https://api.anthropic.com

# ── Max tokens (optional) ────────────────────────────────────────────────────
# Maximum tokens per LLM response. Defaults depend on provider.
max_tokens: 8192

# ── Temperature (optional) ───────────────────────────────────────────────────
# 0.0 = deterministic, 1.0 = creative.
# Default 0.3 - security research prioritizes precision over creativity.
temperature: 0.3

# ── Per-phase overrides (optional) ───────────────────────────────────────────
# Override system prompt or user prefix for specific phases.
# Omit this section to use Hyperdope's built-in defaults.
phases:
  profile:
    # Completely replace the default system prompt
    system: |
      You are a senior threat modeller specialising in cloud-native applications...

  audit:
    # Override only the beginning of the user message
    user_prefix: "Focus only on injection vulnerabilities in this Node.js app.\n\n"

  assess:
    # Use a cheaper / faster model for this phase
    model: claude-haiku-4-5

  draft_ghsa:
    system: |
      You are a security advisory writer. Format all output as GHSA-schema JSON.

  verify:
    # Add special requirements for verification
    user_prefix: "This is a Rust project - focus on memory safety issues.\n\n"
```

---

## Providers and Default Environment Variables

If `api_key` is omitted in YAML, the provider automatically reads its corresponding environment variable:

| Provider | `provider` | Default Env Var | Example Model |
|---|---|---|---|
| Anthropic | `claude` | `ANTHROPIC_API_KEY` | `claude-opus-4-5`, `claude-sonnet-4-5`, `claude-haiku-4-5` |
| OpenAI | `openai` | `OPENAI_API_KEY` | `gpt-4o`, `gpt-4o-mini`, `gpt-4-turbo` |
| Google | `gemini` | `GOOGLE_API_KEY` | `gemini-2.5-pro`, `gemini-2.5-flash` |
| Ollama | `ollama` | *(none required)* | `llama3.3:70b`, `qwen2.5-coder:32b` |

---

## Per-Provider Configuration

### Claude (Anthropic)

```yaml
provider: claude
model:    claude-opus-4-5
api_key:  ${ANTHROPIC_API_KEY}
# Or omit api_key if ANTHROPIC_API_KEY is already set in environment
```

### OpenAI

```yaml
provider: openai
model:    gpt-4o
api_key:  ${OPENAI_API_KEY}
```

### Azure OpenAI

```yaml
provider: openai
model:    gpt-4o                              # your deployment name
api_key:  ${AZURE_OPENAI_API_KEY}
base_url: https://your-resource.openai.azure.com/openai/deployments/gpt-4o
```

### Gemini (Google)

```yaml
provider: gemini
model:    gemini-2.5-pro
api_key:  ${GOOGLE_API_KEY}
```

### Ollama (local, no API key required)

```bash
# Pull model first
ollama pull llama3.3:70b
```

```yaml
provider: ollama
model:    llama3.3:70b
# base_url defaults to http://localhost:11434 - omit if using default port
```

> **Note:** Local models typically underperform cloud models on complex phases such as `audit` and `assess`.
> Cloud models are recommended for production research.

---

## Environment Variable Resolution

Any value matching `${VAR_NAME}` syntax is resolved from the environment when loading configuration:

```yaml
api_key: ${ANTHROPIC_API_KEY}    # ✅ secure - reads from env
api_key: sk-ant-api03-abc123     # ❌ hardcoded - hd_scan will flag as "Hardcoded credential"
```

Resolution priority when looking for API keys:
1. `api_key` field in YAML (after resolving env vars)
2. Provider's default environment variable (`ANTHROPIC_API_KEY`, etc.)
3. Runtime error if neither is present

---

## `HYPERDOPE_AGENT` Environment Variable

To specify an agent config that lives **outside the working directory** (for example: a shared config file used across multiple projects):

```bash
export HYPERDOPE_AGENT=/home/user/.config/hyperdope/agent.yaml
```

When this environment variable is set, the `agent` parameter in tool calls is still required but will be overridden by `HYPERDOPE_AGENT`.

> Use this when working across multiple projects to avoid copying `agent.yaml` into every directory.

---

## Per-Phase Model Overrides

Each phase can use a different model - useful for optimizing costs:

```yaml
provider: claude
model:    claude-opus-4-5     # default model for all phases

phases:
  profile:
    model: claude-sonnet-4-5  # lighter phase, use cheaper model
  audit:
    model: claude-opus-4-5    # heaviest phase - keep strongest model
  confirm:
    model: claude-sonnet-4-5
  assess:
    model: claude-sonnet-4-5
  draft_ghsa:
    model: claude-haiku-4-5   # final phase, formatting output - fast model is sufficient
  disclose:
    model: claude-haiku-4-5
```

---

## Security

| | |
|---|---|
| **Do not commit `agent.yaml`** | Add to `.gitignore`. `hd_scan` flags this file if it detects hardcoded keys. |
| **`base_url` is validated** | HTTPS only (except localhost). Blocked: `169.254.169.254`, `metadata.google.internal`, RFC1918 ranges (`10.x`, `172.16-31.x`, `192.168.x`). |
| **Path traversal protection** | `agent` parameter in tool calls is restricted within CWD. Use `HYPERDOPE_AGENT` env var to point to files outside CWD. |
