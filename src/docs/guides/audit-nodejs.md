# Audit Node.js Project - End to End

Complete guide: from dependency scanning to disclosure package generation for a Node.js project.

---

## Setup

```bash
# 1. Install Hyperdope
npm install -g hyperdope

# 2. Create agent config
cp agent.example.yaml agent.yaml

# 3. Set API key
export ANTHROPIC_API_KEY=sk-ant-api03-...

# 4. Add agent.yaml to gitignore
echo "agent.yaml" >> .gitignore
```

---

## Fastest Method - Single-Command `hd-run`

```bash
# Run all 6 phases with realtime streaming output
npx hd-run --agent agent.yaml \
  --target https://github.com/your-org/your-repo

# Save full results to a JSON file
npx hd-run --agent agent.yaml \
  --target https://github.com/your-org/your-repo \
  --out result.json
```

Realtime output:

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

## Controlled Step-by-Step Execution

### Scan Dependencies First (Zero API Cost)

```bash
npx hd-ci --target ./     # Formatted terminal UI
# or
npx hd-run --agent agent.yaml --target ./ --phase scan
```

Output:

```
  ✓  Scan complete: 487 pkgs  ·  3 CVEs  ·  0 secrets

  [HIGH    ] 2 findings
    · lodash@4.17.20 - Prototype pollution
        npm:lodash@4.17.20
    · semver@5.7.1 - ReDoS vulnerability
        npm:semver@5.7.1
  [MEDIUM  ] 1 finding
    · express@4.17.1 - Open redirect
        npm:express@4.17.1
```

**If `secrets_found > 0`:** Rotate that credential immediately and purge it from git history before proceeding.

**If `hooks_found > 0`:** Inspect the `hook_cmd` field. Patterns such as `curl | bash` or `wget` in `postinstall` indicate potential supply chain risks.

---

### Phase-by-Phase in MCP Client

To inspect findings after each step in Claude Desktop or Cursor:

**Step 1 - Map Attack Surface:**

```
Call hd_profile with:
  agent  = "agent.yaml"
  target = "https://github.com/your-org/your-repo"
```

Output returns a JSON object. **Save the full `raw` field** - this string is passed into `context` in the next step.

**Step 2 - Hunt Vulnerabilities:**

```
Call hd_audit with:
  agent   = "agent.yaml"
  target  = "https://github.com/your-org/your-repo"
  context = {
    "profile": "<paste entire raw string from hd_profile here>"
  }
```

> **Context Passing Guidelines:**
> - `context` is a JSON object with key = phase name, value = **raw string** (unparsed)
> - In Claude Desktop: Claude will automatically extract and forward context - simply instruct "use the output from the previous step"
> - When invoking via custom code/API: copy `result.context` from the prior phase output and pass it intact into the next phase

**Step 3 - Generate PoCs:**

```
Call hd_confirm with context from both profile + audit:
  context = {
    "profile": "...",
    "audit":   "<raw string from hd_audit>"
  }
```

Sample returned PoC:

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
4. Actual: Returns file contents - CONFIRMED

Payload alternatives:
  - ../../etc/shadow
  - ../../root/.ssh/id_rsa
  - ../../../../proc/self/environ  (leaks env vars including secrets)
```

**Step 4 - Calculate CVSS:**

```
Call hd_assess with:
  context = {
    "audit":   "...",
    "confirm": "<raw from hd_confirm>"
  }
```

Sample output:

```json
{
  "vulnerability_id": "HD-2026-001",
  "title":            "Path Traversal in /api/download",
  "cvss_vector":      "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
  "cvss_score":       6.5,
  "severity":         "high",
  "reasoning": {
    "AV": "Network - endpoint accessible over internet",
    "AC": "Low - no special preconditions",
    "PR": "Low - requires valid auth token (guest account works)",
    "UI": "None",
    "S":  "Unchanged",
    "C":  "High - arbitrary file read on server",
    "I":  "None - read-only exploit",
    "A":  "None"
  }
}
```

**Steps 5–6 - Draft Advisory + Disclosure Package:**

```
Call hd_draft_ghsa → hd_disclose with accumulated context from earlier steps
```

---

## Node.js-Specific Tips

### Target as GitHub URL vs Local Path

```yaml
# ✅ For LLM phases - model fetches remote repository tree
target: https://github.com/your-org/your-repo

# ✅ For hd_scan - requires local directory with lockfiles
target: /path/to/local/repo
```

### TypeScript Projects

Override `user_prefix` in `agent.yaml` to focus attention on `.ts` files:

```yaml
phases:
  audit:
    user_prefix: |
      This is a TypeScript project. Focus on .ts and .tsx files.
      Check for type assertions (as any, as unknown) that bypass type safety.
      Common TypeScript-specific risks: unsafe type casting, prototype pollution
      in generic utility functions, deserialization without type guards.
```

### Prototype Pollution - Commonly Overlooked

Node.js-specific and highly prevalent. While the audit phase checks for this automatically, you can emphasize it:

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

### Monorepo Architectures

```bash
# Scan each package independently
npx hd-ci --target ./packages/api      --sarif-out api.sarif.json
npx hd-ci --target ./packages/frontend --sarif-out frontend.sarif.json

# Audit public-facing API sub-tree
npx hd-run --agent agent.yaml --target https://github.com/org/repo/tree/main/packages/api
```

### Express Middleware Registration Order Bugs

Commonly missed: authentication middleware registered **after** route definitions → routes remain unprotected.

```yaml
phases:
  audit:
    user_prefix: |
      For Express apps: verify that auth middleware is registered BEFORE all
      route definitions it's supposed to protect. Check app.use() call order.
      A route defined before auth middleware registers is unprotected.
```

---

## Resuming Interrupted Runs

A full pipeline takes ~5–15 minutes depending on model and target size. If interrupted:

```bash
# Locate existing session file
ls .hyperdope-session-*.json

# Resume from the interrupted phase
npx hd-run --agent agent.yaml \
  --target https://github.com/your-org/your-repo \
  --resume-from confirm \
  --session-file .hyperdope-session-20260825T141032.json
```

---

## Verifying Patches After Vendor Fix

```bash
npx hd-run --agent agent.yaml \
  --target "v2.3.1 - diff: https://github.com/org/repo/compare/v2.3.0...v2.3.1" \
  --phase verify
```

Or via MCP tool `hd_verify`:

```
Call hd_verify with:
  agent   = "agent.yaml"
  target  = "v2.3.1 (commit abc1234def) - fix applied in src/download.js"
  context = {
    "audit":   "...",
    "confirm": "...",
    "assess":  "..."
  }
```

Sample result:

```json
{
  "verification_results": [
    {
      "finding_id":       "HD-2026-001",
      "original_title":   "Path Traversal in /api/download",
      "verdict":          "PARTIAL_FIX",
      "q1_root_cause":    "path.join(baseDir, userInput) without realpath+startsWith check",
      "q2_change_analysis": "Fix applied to /api/download handler but same pattern exists in /api/export",
      "q3_bypass_vector": "GET /api/export?file=../../etc/passwd - same vulnerability, different endpoint",
      "q4_sibling_sites": "/api/export at src/routes/export.js:43 - identical pattern, not patched",
      "recommended_action": "Apply same realpath()+startsWith() fix to src/routes/export.js:43"
    }
  ],
  "overall_status": "partially_patched"
}
```

`PARTIAL_FIX` = the patch fixes one endpoint, but leaves other endpoints or bypasses vulnerable. This highlights the exact value of `hd_verify` - catching incomplete vendor fixes.
