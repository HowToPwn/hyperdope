# Agent YAML Reference

Mọi tool call của Hyperdope đều nhận param `agent` — đường dẫn đến file YAML config này. File định nghĩa provider LLM, model, và các override tùy chọn theo từng phase.

---

## Ví dụ tối thiểu

```yaml
provider: claude
model:    claude-opus-4-5
api_key:  ${ANTHROPIC_API_KEY}
```

---

## Full reference

```yaml
# ── Provider ──────────────────────────────────────────────────────────────────
# Bắt buộc. Một trong: claude | openai | gemini | ollama
provider: claude

# ── Model ────────────────────────────────────────────────────────────────────
# Bắt buộc. Model ID của provider đã chọn.
model: claude-opus-4-5

# ── API key ──────────────────────────────────────────────────────────────────
# Dùng cú pháp ${ENV_VAR} để đọc từ environment — không hardcode vào file.
# Có thể bỏ field này nếu bạn đã set env var chuẩn của provider (xem bảng bên dưới).
api_key: ${ANTHROPIC_API_KEY}

# ── Base URL (tuỳ chọn) ───────────────────────────────────────────────────────
# Override endpoint API. Dùng cho:
#   - Azure OpenAI:               https://your-resource.openai.azure.com
#   - OpenAI-compatible proxy:    http://localhost:8080
#   - Ollama (mặc định):          http://localhost:11434
#
# Bảo mật: base_url bị validate khi gọi — chỉ HTTPS (hoặc HTTP cho localhost),
# không cho phép địa chỉ RFC1918 và IMDS metadata host.
base_url: https://api.anthropic.com

# ── Max tokens (tuỳ chọn) ────────────────────────────────────────────────────
# Số token tối đa cho mỗi response LLM. Mặc định tuỳ provider.
max_tokens: 8192

# ── Temperature (tuỳ chọn) ───────────────────────────────────────────────────
# 0.0 = deterministic, 1.0 = creative.
# Mặc định 0.3 — security research ưu tiên chính xác hơn sáng tạo.
temperature: 0.3

# ── Per-phase overrides (tuỳ chọn) ───────────────────────────────────────────
# Override system prompt hoặc user prefix cho từng phase cụ thể.
# Bỏ section này nếu muốn dùng prompt mặc định của Hyperdope.
phases:
  profile:
    # Thay hoàn toàn system prompt mặc định
    system: |
      You are a senior threat modeller specialising in cloud-native applications...

  audit:
    # Chỉ override phần đầu user message
    user_prefix: "Focus only on injection vulnerabilities in this Node.js app.\n\n"

  assess:
    # Dùng model rẻ hơn / nhanh hơn cho phase này
    model: claude-haiku-4-5

  draft_ghsa:
    system: |
      You are a security advisory writer. Format all output as GHSA-schema JSON.

  verify:
    # Thêm yêu cầu đặc biệt cho verification
    user_prefix: "This is a Rust project — focus on memory safety issues.\n\n"
```

---

## Provider và env var mặc định

Nếu bỏ `api_key` trong YAML, provider tự đọc env var tương ứng:

| Provider | `provider` | Env var mặc định | Model ví dụ |
|---|---|---|---|
| Anthropic | `claude` | `ANTHROPIC_API_KEY` | `claude-opus-4-5`, `claude-sonnet-4-5`, `claude-haiku-4-5` |
| OpenAI | `openai` | `OPENAI_API_KEY` | `gpt-4o`, `gpt-4o-mini`, `gpt-4-turbo` |
| Google | `gemini` | `GOOGLE_API_KEY` | `gemini-2.5-pro`, `gemini-2.5-flash` |
| Ollama | `ollama` | *(không cần)* | `llama3.3:70b`, `qwen2.5-coder:32b` |

---

## Config từng provider

### Claude (Anthropic)

```yaml
provider: claude
model:    claude-opus-4-5
api_key:  ${ANTHROPIC_API_KEY}
# Hoặc bỏ api_key nếu ANTHROPIC_API_KEY đã set trong env
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
model:    gpt-4o                              # deployment name của bạn
api_key:  ${AZURE_OPENAI_API_KEY}
base_url: https://your-resource.openai.azure.com/openai/deployments/gpt-4o
```

### Gemini (Google)

```yaml
provider: gemini
model:    gemini-2.5-pro
api_key:  ${GOOGLE_API_KEY}
```

### Ollama (local, không cần API key)

```bash
# Pull model trước
ollama pull llama3.3:70b
```

```yaml
provider: ollama
model:    llama3.3:70b
# base_url mặc định là http://localhost:11434 — bỏ nếu dùng port mặc định
```

> **Lưu ý:** Model local thường kém hơn cloud model trong các phase phức tạp như `audit` và `assess`.
> Khuyến nghị dùng cloud model cho production research.

---

## Environment variable resolution

Bất kỳ giá trị nào có dạng `${VAR_NAME}` sẽ được resolve từ environment khi load config:

```yaml
api_key: ${ANTHROPIC_API_KEY}    # ✅ an toàn — đọc từ env
api_key: sk-ant-api03-abc123     # ❌ hardcode — hd_scan sẽ flag là "Hardcoded credential"
```

Thứ tự ưu tiên khi tìm API key:
1. Field `api_key` trong YAML (sau khi resolve env var)
2. Env var mặc định của provider (`ANTHROPIC_API_KEY`, v.v.)
3. Lỗi tại runtime nếu không có cả hai

---

## Env var `HYPERDOPE_AGENT`

Nếu muốn chỉ định agent config nằm **ngoài working directory** (ví dụ: file config dùng chung cho nhiều project):

```bash
export HYPERDOPE_AGENT=/home/user/.config/hyperdope/agent.yaml
```

Khi set env var này, `agent` param trong tool call vẫn cần truyền nhưng sẽ bị override bởi `HYPERDOPE_AGENT`.

> Dùng khi làm việc với nhiều project và không muốn copy `agent.yaml` vào từng thư mục.

---

## Per-phase model override

Mỗi phase có thể dùng model khác nhau — hữu ích để tiết kiệm chi phí:

```yaml
provider: claude
model:    claude-opus-4-5     # model mặc định cho mọi phase

phases:
  profile:
    model: claude-sonnet-4-5  # phase nhẹ hơn, dùng model rẻ hơn
  audit:
    model: claude-opus-4-5    # phase nặng nhất — giữ model mạnh
  confirm:
    model: claude-sonnet-4-5
  assess:
    model: claude-sonnet-4-5
  draft_ghsa:
    model: claude-haiku-4-5   # phase cuối, format output — model nhanh là đủ
  disclose:
    model: claude-haiku-4-5
```

---

## Bảo mật

| | |
|---|---|
| **Không commit `agent.yaml`** | Thêm vào `.gitignore`. `hd_scan` flag file này nếu phát hiện hardcoded key. |
| **`base_url` bị validate** | HTTPS only (trừ localhost). Không cho phép: `169.254.169.254`, `metadata.google.internal`, dải RFC1918 (`10.x`, `172.16-31.x`, `192.168.x`). |
| **Path traversal protection** | `agent` param trong tool call bị restrict trong CWD. Dùng `HYPERDOPE_AGENT` env var để trỏ đến file ngoài CWD. |
