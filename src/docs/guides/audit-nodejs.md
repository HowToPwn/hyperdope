# Audit Node.js Project — End to End

Hướng dẫn đầy đủ: từ dependency scan đến gói disclosure cho một Node.js project.

---

## Setup

```bash
# 1. Cài Hyperdope
npm install -g hyperdope

# 2. Tạo agent config
cp agent.example.yaml agent.yaml

# 3. Set API key
export ANTHROPIC_API_KEY=sk-ant-api03-...

# 4. Thêm agent.yaml vào gitignore
echo "agent.yaml" >> .gitignore
```

---

## Cách nhanh nhất — `hd-run` một lệnh

```bash
# Chạy toàn bộ 6 phase, kết quả xuất realtime
npx hd-run --agent agent.yaml \
  --target https://github.com/your-org/your-repo

# Lưu kết quả ra file JSON
npx hd-run --agent agent.yaml \
  --target https://github.com/your-org/your-repo \
  --out result.json
```

Output realtime:

```
╔════════════════════════════════════════════════════════╗
║ ❯ hd-run  ·  Full Pipeline                            ║
║   github.com/your-org/your-repo                       ║
╚════════════════════════════════════════════════════════╝

  Target    https://github.com/your-org/your-repo
  Agent     agent.yaml

  ✓  1/6  Profile      → 8 surface categories
  ✓  2/6  Audit        → 3 candidates
    · [HIGH] Unsanitized path in /api/download
    · [HIGH] SSRF via webhook URL
    · [MED]  Missing rate limit on /auth/login
  ⠹  3/6  Confirm      generating PoCs…
  ✓  3/6  Confirm      → 2 PoCs generated
  ✓  4/6  Assess       → max CVSS 8.7  (3 findings)
  ✓  5/6  Draft GHSA   → advisory drafted
  ✓  6/6  Disclose     → disclosure package ready

  Session   .hyperdope-session-20260825T141032.json

  ╔════════════════════════════════════════════════╗
  ║  ✓  PASS  6/6 phases complete                 ║
  ╚════════════════════════════════════════════════╝
```

---

## Cách kiểm soát từng phase — step by step

### Scan dependencies trước (không tốn API)

```bash
npx hd-ci --target ./     # Terminal output đẹp
# hoặc
npx hd-run --agent agent.yaml --target ./ --phase scan
```

Output:

```
  ✓  Scan complete: 487 pkgs  ·  3 CVEs  ·  0 secrets

  [HIGH    ] 2 findings
    · lodash@4.17.20 — Prototype pollution
        npm:lodash@4.17.20
    · semver@5.7.1 — ReDoS vulnerability
        npm:semver@5.7.1
  [MEDIUM  ] 1 finding
    · express@4.17.1 — Open redirect
        npm:express@4.17.1
```

**Nếu thấy `secrets_found > 0`:** Rotate ngay credential đó và xóa khỏi git history trước khi tiếp tục.

**Nếu thấy `hooks_found > 0`:** Kiểm tra field `hook_cmd`. Pattern `curl | bash` hoặc `wget` trong `postinstall` = nguy cơ supply chain.

---

### Phase-by-phase trong MCP client

Nếu muốn xem kết quả từng bước trong Claude Desktop hoặc Cursor:

**Bước 1 — Map attack surface:**

```
Gọi hd_profile với:
  agent  = "agent.yaml"
  target = "https://github.com/your-org/your-repo"
```

Output trả về object JSON. **Lưu lại toàn bộ field `raw`** — đây là string sẽ truyền vào `context` bước sau.

**Bước 2 — Hunt vulnerabilities:**

```
Gọi hd_audit với:
  agent   = "agent.yaml"
  target  = "https://github.com/your-org/your-repo"
  context = {
    "profile": "<paste toàn bộ raw string từ hd_profile ở đây>"
  }
```

> **Cách truyền context đúng:**
> - `context` là object JSON với key = tên phase, value = **chuỗi raw** (không parse)
> - Nếu dùng trong Claude Desktop: Claude sẽ tự trích xuất và truyền context — chỉ cần nói "dùng output từ bước trước"
> - Nếu tự gọi qua code/API: copy field `result.context` từ output phase trước và truyền nguyên vào phase sau

**Bước 3 — Generate PoC:**

```
Gọi hd_confirm với context từ cả profile + audit:
  context = {
    "profile": "...",
    "audit":   "<raw string từ hd_audit>"
  }
```

PoC mẫu trả về:

```
## PoC 1: Path Traversal via /api/download

Reliability: deterministic
Detection: low

Steps:
1. Authenticate as any user (guest account sufficient)
2. Send request:
   curl -s "https://target.com/api/download?file=../../etc/passwd" \
     -H "Authorization: Bearer <any_valid_token>"
3. Expected: 200 OK with content of /etc/passwd
4. Actual: Returns file contents — CONFIRMED

Payload alternatives:
  - ../../etc/shadow
  - ../../root/.ssh/id_rsa
  - ../../../../proc/self/environ  (leaks env vars including secrets)
```

**Bước 4 — Tính CVSS:**

```
Gọi hd_assess với:
  context = {
    "audit":   "...",
    "confirm": "<raw từ hd_confirm>"
  }
```

Output mẫu:

```json
{
  "vulnerability_id": "HD-2026-001",
  "title":            "Path Traversal in /api/download",
  "cvss_vector":      "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
  "cvss_score":       6.5,
  "severity":         "high",
  "reasoning": {
    "AV": "Network — endpoint accessible over internet",
    "AC": "Low — no special preconditions",
    "PR": "Low — requires valid auth token (guest account works)",
    "UI": "None",
    "S":  "Unchanged",
    "C":  "High — arbitrary file read on server",
    "I":  "None — read-only exploit",
    "A":  "None"
  }
}
```

**Bước 5–6 — Draft advisory + Disclosure:**

```
Gọi hd_draft_ghsa → hd_disclose với context tích lũy từ các bước trước
```

---

## Tips đặc thù cho Node.js

### Target là GitHub URL thay vì local path

```yaml
# ✅ Cho LLM phase — model fetch source tree
target: https://github.com/your-org/your-repo

# ✅ Cho hd_scan — cần local path có lockfile
target: /path/to/local/repo
```

### TypeScript project

Override `user_prefix` trong `agent.yaml` để model chú ý `.ts` files:

```yaml
phases:
  audit:
    user_prefix: |
      This is a TypeScript project. Focus on .ts and .tsx files.
      Check for type assertions (as any, as unknown) that bypass type safety.
      Common TypeScript-specific risks: unsafe type casting, prototype pollution
      in generic utility functions, deserialization without type guards.

```

### Prototype pollution — thường bị bỏ sót

Node.js-specific và rất phổ biến. Audit phase sẽ check nhưng có thể nhắc thêm:

```yaml
phases:
  audit:
    user_prefix: |
      Pay special attention to prototype pollution:
      - Any function named merge, extend, assign, deepCopy, mixin, defaults
      - Object.assign() calls where destination is not a literal {}
      - for..in loops without hasOwnProperty() check
      - Libraries: lodash <4.17.21, minimist <1.2.6, qs <6.9.7

```

### Monorepo

```bash
# Scan từng package riêng
npx hd-ci --target ./packages/api      --sarif-out api.sarif.json
npx hd-ci --target ./packages/frontend --sarif-out frontend.sarif.json

# Audit phần public-facing
npx hd-run --agent agent.yaml --target https://github.com/org/repo/tree/main/packages/api
```

### Express middleware order bug

Hay bị miss: middleware auth đăng ký **sau** route definition → route không được protect.

```yaml
phases:
  audit:
    user_prefix: |
      For Express apps: verify that auth middleware is registered BEFORE all
      route definitions it's supposed to protect. Check app.use() call order.
      A route defined before auth middleware registers is unprotected.

```

---

## Resume khi bị gián đoạn

Pipeline mất ~5-15 phút tùy model và target size. Nếu bị interrupt:

```bash
# Xem session file đã lưu
ls .hyperdope-session-*.json

# Resume từ phase bị dừng
npx hd-run --agent agent.yaml \
  --target https://github.com/your-org/your-repo \
  --resume-from confirm \
  --session-file .hyperdope-session-20260825T141032.json
```

---

## Verify patch sau khi vendor fix

```bash
npx hd-run --agent agent.yaml \
  --target "v2.3.1 — diff: https://github.com/org/repo/compare/v2.3.0...v2.3.1" \
  --phase verify
```

Hoặc MCP tool `hd_verify`:

```
Gọi hd_verify với:
  agent   = "agent.yaml"
  target  = "v2.3.1 (commit abc1234def) — fix applied in src/download.js"
  context = {
    "audit":   "...",
    "confirm": "...",
    "assess":  "..."
  }
```

Kết quả mẫu:

```json
{
  "verification_results": [
    {
      "finding_id":       "HD-2026-001",
      "original_title":   "Path Traversal in /api/download",
      "verdict":          "PARTIAL_FIX",
      "q1_root_cause":    "path.join(baseDir, userInput) without realpath+startsWith check",
      "q2_change_analysis": "Fix applied to /api/download handler but same pattern exists in /api/export",
      "q3_bypass_vector": "GET /api/export?file=../../etc/passwd — same vulnerability, different endpoint",
      "q4_sibling_sites": "/api/export at src/routes/export.js:43 — identical pattern, not patched",
      "recommended_action": "Apply same realpath()+startsWith() fix to src/routes/export.js:43"
    }
  ],
  "overall_status": "partially_patched"
}
```

`PARTIAL_FIX` = patch chỉ fix một endpoint, còn endpoint khác vẫn vulnerable. Đây chính xác là giá trị của `hd_verify` — phát hiện incomplete patch.
