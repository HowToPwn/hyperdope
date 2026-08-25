# Pipeline — Cách Hyperdope hoạt động

Hyperdope tổ chức security research thành **6 phase tuần tự**, mô phỏng đúng quy trình mà researcher thực tế làm — từ mapping attack surface đến gói disclosure hoàn chỉnh.

---

## Tổng quan

```
Phase 0  hd_scan          ← Không cần LLM. Scan CVE, secret, hook.
   ↓ CVE list, SBOM, secrets, hooks
Phase 1  hd_profile       ← LLM map attack surface (STRIDE)
   ↓ surface categories, trust boundaries, data flows
Phase 2  hd_audit         ← LLM hunt source→sink, control gap
   ↓ candidate vulnerabilities, chain candidates
Phase 3  hd_confirm       ← LLM generate PoC
   ↓ exploit scripts, reliability rating, detection likelihood
Phase 4  hd_assess        ← LLM + math: CVSS v3.1
   ↓ CVSS vector + verified score, blast radius
Phase 5  hd_draft_ghsa    ← LLM draft GHSA advisory
   ↓ advisory schema, remediation priority
Phase 6  hd_disclose      ← LLM tạo disclosure package
   ↓ exec brief + technical advisory + vendor email

(optional)
  hd_verify               ← Sau khi vendor patch: xác nhận fix
   ↓ PATCHED / PARTIAL_FIX / STILL_VULNERABLE / CANNOT_VERIFY
```

---

## Chạy pipeline

### Cách 1 — `hd_run` / `hd-run` (khuyến nghị)

Chạy toàn bộ 6 phase tự động, context được chain và trim tự động:

```bash
# CLI
npx hd-run --agent agent.yaml --target https://github.com/org/repo

# MCP tool
hd_run(agent="agent.yaml", target="https://github.com/org/repo")
```

Session được lưu vào `.hyperdope-session-<timestamp>.json`. Resume nếu bị gián đoạn:

```bash
npx hd-run --agent agent.yaml \
  --target https://github.com/org/repo \
  --resume-from confirm \
  --session-file .hyperdope-session-20260825T141032.json
```

### Cách 2 — Gọi từng tool riêng lẻ

Gọi từng phase trong MCP client, truyền output của phase trước vào `context` của phase sau:

```
# Bước 1
result_profile = hd_profile(agent="agent.yaml", target="...")

# Bước 2 — truyền toàn bộ output của profile vào context
result_audit = hd_audit(
  agent="agent.yaml",
  target="...",
  context={"profile": result_profile.raw}   ← đây là string JSON
)

# Bước 3
result_confirm = hd_confirm(
  agent="agent.yaml",
  target="...",
  context={
    "profile": result_profile.raw,
    "audit":   result_audit.raw
  }
)
```

> **Lưu ý:** `context` nhận object `{phase_name: raw_string}`. Giá trị là **chuỗi JSON** (raw output của phase trước), không phải object đã parse. `hd_run` làm việc này tự động — đó là lý do nên dùng `hd_run` thay vì gọi từng tool.

---

## Context trimming

Mỗi phase trim context trước khi gửi lên LLM để tránh vượt context window. Logic trim:

- Giữ toàn bộ output của **phase ngay trước**
- Tóm tắt hoặc cắt bớt các phase xa hơn
- Không bao giờ trim output của chính phase hiện tại

Ví dụ: khi chạy `assess`, context sẽ có đầy đủ `confirm` và `audit`, nhưng `profile` có thể bị trim nếu quá dài.

---

## Prompt injection mitigation

Mọi content do attacker kiểm soát (target URL, file content, output từ phase trước) đều được wrap trong XML tag:

```
<pipeline_data label="audit_findings">
  { ... JSON audit output ... }
</pipeline_data>
```

System prompt của mỗi phase hướng dẫn model xử lý mọi thứ trong `<pipeline_data>` như **data để phân tích**, không phải instruction. Điều này ngăn repository độc hại inject lệnh vào agent.

---

## Chi tiết từng phase

### Phase 0 — `hd_scan` (không dùng LLM)

**Input:** Đường dẫn thư mục chứa lockfile.

**Làm gì:** Query OSV.dev batch API cho mọi ecosystem được phát hiện. Scan secret trong config file. Kiểm tra npm lifecycle hook.

**Lockfile được hỗ trợ:**

| Ecosystem | File |
|---|---|
| npm | `package-lock.json`, `package.json` |
| Python | `requirements.txt`, `poetry.lock`, `Pipfile.lock` |
| Go | `go.mod` |
| Rust | `Cargo.lock` |

**Output chính:**

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

### Phase 1 — `hd_profile` (LLM)

**Input:** Target descriptor (URL, path, description).

**Làm gì:** Map attack surface dùng STRIDE. Identify data flow, trust boundary, parser, auth mechanism, deserialization, supply chain, LLM surface.

**Output:** Danh sách surface category với priority P0/P1/P2, STRIDE applicability, evidence, attack vectors.

**Tại sao chạy trước?** Không thể hunt hiệu quả nếu không biết những gì tồn tại. Profile là research brief định hướng cho mọi phase sau.

---

### Phase 2 — `hd_audit` (LLM)

**Input:** Target + profile context.

**Làm gì:** 5-step adversarial hunt:
1. Entry point inventory
2. Source → sink tracing
3. Control gap analysis (auth, validation, escaping, serialization)
4. Assumption violation (code assume gì mà attacker có thể vi phạm?)
5. Chain candidate identification

**Output:** Candidate vulnerabilities với title, CWE, affected component, attack scenario, severity estimate.

---

### Phase 3 — `hd_confirm` (LLM)

**Input:** Target + audit findings.

**Làm gì:** Generate tối đa 3 PoC per finding, xếp theo exploitability. Mỗi PoC gồm:
- Trigger sequence step-by-step
- Payload / request mẫu
- Expected vs actual outcome
- Reliability rating: `deterministic` / `probabilistic` / `timing-dependent`
- Detection likelihood: `low` / `medium` / `high`

**Tại sao trước CVSS?** Metric CVSS (Attack Complexity, Privileges Required, User Interaction) được đặt dựa trên PoC thực tế — không phải ước tính.

---

### Phase 4 — `hd_assess` (LLM + math)

**Input:** Target + audit + confirm context.

**Làm gì:** Assign CVSS v3.1 vector với per-metric chain-of-thought. Score được **tính toán toán học từ vector** — LLM không thể hallucinate số không khớp vector. Cũng ước tính blast radius, chaining potential, và scope (S:C khi vượt security boundary).

**Output ví dụ:**

```json
{
  "vulnerability_id": "HD-2026-001",
  "cvss_vector":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  "cvss_score":       9.1,
  "severity":         "critical",
  "reasoning": {
    "AV": "Network — reachable over internet without physical access",
    "AC": "Low — no special conditions required",
    "PR": "None — unauthenticated endpoint",
    "UI": "None — no victim interaction needed",
    "S":  "Unchanged — attacker cannot jump to other systems",
    "C":  "High — arbitrary file read leaks all server secrets",
    "I":  "High — arbitrary file write achieves RCE",
    "A":  "None — service remains available"
  }
}
```

---

### Phase 5 — `hd_draft_ghsa` (LLM)

**Input:** Target + audit + confirm + assess context.

**Làm gì:** Generate GitHub Security Advisory draft theo GHSA schema, bao gồm:
- Package name + affected version range
- CWE IDs
- CVSS vector
- Description (executive summary + technical root cause)
- Remediation guidance
- Priority: P1 (7 ngày) / P2 (30 ngày) / P3 (90 ngày)
- Disclosure readiness checklist

---

### Phase 6 — `hd_disclose` (LLM)

**Input:** Toàn bộ context các phase trước.

**Làm gì:** Generate disclosure package hoàn chỉnh:
1. **Executive brief** — 3–5 câu, dành cho CISO / VP Engineering
2. **Full technical advisory** — root cause, PoC, impact, IoCs, remediation diff
3. **Vendor notification email** — professional tone, 90-day timeline table

---

### `hd_verify` — Patch verification (LLM)

**Chạy khi nào:** Sau khi vendor release patch.

**Input:** Patch descriptor (commit SHA, version tag, diff URL) + audit/confirm/assess context.

**Methodology — 4 câu hỏi:**
- **Q1:** Root cause chính xác là gì? (function, file, điều kiện lỗi)
- **Q2:** Patch thay đổi gì? Có đúng chỗ root cause không?
- **Q3:** PoC gốc còn trigger được qua path khác hay encoding khác không?
- **Q4:** Có sibling site nào cùng pattern mà patch bỏ sót không?

**Verdicts:**

| Verdict | Ý nghĩa |
|---|---|
| `PATCHED` | Root cause được xử lý ở mọi call site. PoC không còn work. |
| `PARTIAL_FIX` | Patch một vector nhưng còn bypass hoặc sibling chưa fix. |
| `STILL_VULNERABLE` | Patch không có hoặc không hiệu quả. PoC vẫn work. |
| `CANNOT_VERIFY` | Không đủ thông tin (không có diff/source) để kết luận. |
