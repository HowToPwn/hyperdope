# Hyperdope — Quickstart

Từ zero đến finding đầu tiên trong 5 phút.

---

## Yêu cầu

| | |
|---|---|
| **Node.js** | ≥ 20 — kiểm tra: `node --version` |
| **API key** | Anthropic, OpenAI, Google, hoặc Ollama local |
| **MCP client** | Claude Desktop, Cursor, hoặc bất kỳ MCP client nào |

---

## Bước 1 — Cài đặt

```bash
# Cài global (dùng được npx hd-ci / hd-run ở bất kỳ đâu)
npm install -g hyperdope

# Hoặc chạy thẳng không cài:
npx hyperdope
```

---

## Bước 2 — Tạo agent config

```bash
# Copy từ template
cp agent.example.yaml agent.yaml
```

Sửa `agent.yaml` — chọn provider và điền model:

```yaml
# agent.yaml — Claude (khuyến nghị)
provider: claude
model:    claude-opus-4-5
api_key:  ${ANTHROPIC_API_KEY}    # đọc từ env, không hardcode
```

Đặt env var:

```bash
# Linux / macOS
export ANTHROPIC_API_KEY=sk-ant-api03-...

# Windows PowerShell
$env:ANTHROPIC_API_KEY = "sk-ant-api03-..."

# Windows CMD
set ANTHROPIC_API_KEY=sk-ant-api03-...
```

> **Bảo mật:** Thêm `agent.yaml` vào `.gitignore` — file này có thể chứa API key.
> `hd_scan` sẽ tự flag nếu bạn quên hardcode key vào YAML.

Xem đầy đủ các provider và option tại [concepts/agent-yaml.md](concepts/agent-yaml.md).

---

## Bước 3 — Kết nối MCP client

### Claude Desktop

Tìm file config theo OS:

| OS | Đường dẫn |
|---|---|
| **macOS** | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| **Windows** | `%APPDATA%\Claude\claude_desktop_config.json` |
| **Linux** | `~/.config/Claude/claude_desktop_config.json` |

Thêm vào file (tạo mới nếu chưa có):

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

**Hoặc** nếu đã cài global:

```json
{
  "mcpServers": {
    "hyperdope": {
      "command": "hyperdope"
    }
  }
}
```

Sau đó **khởi động lại Claude Desktop**. Vào Settings → Developer → MCP Servers, thấy `hyperdope` ở trạng thái Connected là OK.

### Cursor / VS Code

Thêm vào `.cursor/mcp.json` hoặc `.vscode/mcp.json`:

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

## Bước 4 — Scan đầu tiên (không cần LLM)

`hd_scan` gọi thẳng OSV.dev — không cần API key, không tốn tiền.

**Cách 1 — Dùng CLI `hd-ci` (nhanh nhất):**

```bash
npx hd-ci --target /path/to/your/project
```

Output mẫu:

```
╔════════════════════════════════════════════════════════╗
║ ❯ Hyperdope  hd-ci                                     ║
╚════════════════════════════════════════════════════════╝

  Target      /path/to/your/project
  Threshold   HIGH

  ✓  Scan complete: 312 pkgs  ·  2 CVEs  ·  0 secrets

  [HIGH    ] 2 findings
    · lodash@4.17.20 — Prototype pollution
        npm:lodash@4.17.20
    · semver@5.7.1 — ReDoS
        npm:semver@5.7.1

  ╔════════════════════════════════════════════════╗
  ║  ✗  FAIL  2 finding(s) ≥ HIGH                 ║
  ╚════════════════════════════════════════════════╝
```

**Cách 2 — Dùng MCP tool `hd_scan`** (trong Claude Desktop / Cursor):

```
Gọi tool hd_scan với target = "/path/to/your/project"
```

Output JSON trả về gồm:
- `findings[]` — CVEs, secrets, hooks
- `meta.packages_scanned` — số package đã scan
- `sbom` — danh sách toàn bộ dependency

---

## Bước 5 — Chạy full audit pipeline

### Cách 1 — Standalone CLI `hd-run` (khuyến nghị cho bắt đầu)

Không cần MCP client, chạy thẳng từ terminal:

```bash
npx hd-run --agent agent.yaml --target https://github.com/org/repo
```

Output realtime:

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

Chạy một phase đơn lẻ:

```bash
# Chỉ chạy scan
npx hd-run --agent agent.yaml --target ./ --phase scan

# Chỉ chạy audit
npx hd-run --agent agent.yaml --target https://github.com/org/repo --phase audit
```

### Cách 2 — Dùng MCP tool `hd_run` (trong Claude Desktop / Cursor)

```
Gọi tool hd_run với:
  agent  = "agent.yaml"
  target = "https://github.com/org/repo"
```

Pipeline sẽ chạy tuần tự: `profile → audit → confirm → assess → draft_ghsa → disclose`

Session file được lưu tự động.

---

## Bước 6 — Resume khi bị gián đoạn

Nếu pipeline dừng giữa chừng (lỗi mạng, hết token, v.v.), resume từ phase bị dừng:

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

Hyperdope đọc context của các phase đã xong từ session file, bỏ qua chúng và tiếp tục từ `confirm`.

---

## Bước 7 — Verify patch sau khi vendor fix

```bash
npx hd-run --agent agent.yaml \
  --target "v2.3.1 (commit abc1234)" \
  --phase verify
```

Hoặc MCP tool `hd_verify` với context từ audit + confirm + assess.

Kết quả trả về verdict cho từng finding: `PATCHED` / `PARTIAL_FIX` / `STILL_VULNERABLE` / `CANNOT_VERIFY`.

---

## Tích hợp CI/CD

```bash
# Fail build nếu có CVE mức High trở lên
npx hd-ci --target ./ --sarif-out results.sarif.json
# exit 0 = PASS, exit 1 = FAIL
```

Xem hướng dẫn đầy đủ tại [guides/ci-integration.md](guides/ci-integration.md).

---

## Troubleshooting

### "Cannot find module" hoặc "command not found"

```bash
# Kiểm tra Node.js version (phải ≥ 20)
node --version

# Cài lại
npm install -g hyperdope@latest
```

### "base_url must use HTTPS" hoặc "blocked metadata host"

`base_url` trong `agent.yaml` trỏ đến địa chỉ nội bộ hoặc dùng HTTP. Xem [concepts/agent-yaml.md](concepts/agent-yaml.md#security) để biết các địa chỉ bị chặn.

### "Agent config path must be within the working directory"

```bash
# Dùng env var thay vì path tương đối
export HYPERDOPE_AGENT=/absolute/path/to/agent.yaml
```

Hoặc chạy từ đúng thư mục chứa `agent.yaml`.

### Tool không xuất hiện trong Claude Desktop

1. Kiểm tra JSON config hợp lệ: `cat ~/Library/Application\ Support/Claude/claude_desktop_config.json | python3 -m json.tool`
2. Kiểm tra `npx hyperdope` chạy được trong terminal cùng user với Claude Desktop
3. Xem log MCP: Claude Desktop → Settings → Developer → Logs

### OSV API trả về lỗi

```bash
# Test trực tiếp
curl -s https://api.osv.dev/v1/query -d '{"package":{"name":"lodash","ecosystem":"npm"},"version":"4.17.20"}' | head -c 200
```

Nếu OSV down, `hd_scan` vẫn trả về secret detection và hook analysis; CVE list sẽ có `osv_error` trong `meta`.

---

## Bước tiếp theo

| Tài liệu | Nội dung |
|---|---|
| [concepts/pipeline.md](concepts/pipeline.md) | Hiểu 6 phase, context flow, injection mitigation |
| [concepts/agent-yaml.md](concepts/agent-yaml.md) | Toàn bộ config option, 4 provider |
| [guides/audit-nodejs.md](guides/audit-nodejs.md) | Audit Node.js project từ đầu đến cuối |
| [guides/ci-integration.md](guides/ci-integration.md) | GitHub Actions workflow, SARIF, weekly scan |
