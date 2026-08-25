# Guide: GitHub Actions CI Integration

Run `hd-ci` as part of your pull request checks to catch new CVEs, hardcoded secrets, and suspicious supply chain hooks before they reach production.

---

## What `hd-ci` does

1. Scans all detected lockfiles (`package-lock.json`, `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `go.mod`, `Cargo.lock`) against OSV.dev
2. Runs secret detection on config files in the project root
3. Checks npm `postinstall` / `preinstall` hooks for network download patterns
4. Exports results as SARIF 2.1.0 for GitHub Code Scanning
5. Exits with code 1 if any finding meets or exceeds the severity threshold

No LLM API key is required.

---

## Basic workflow

```yaml
# .github/workflows/hyperdope-scan.yml
name: Hyperdope Security Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  hd-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # required for uploading SARIF

    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # pin by SHA

      - uses: actions/setup-node@39370e3970a6d050c480ffad4ff0ed4d3fdee5af
        with:
          node-version: '20'

      - name: Run Hyperdope CI scan
        run: npx hd-ci --target ./ --sarif-out hd-results.sarif.json
        # Exit code 1 if any High/Critical finding — fails the job

      - name: Upload SARIF to GitHub Code Scanning
        if: always()   # upload even if the scan step fails
        uses: github/codeql-action/upload-sarif@4dd16135b69a43b6c8efb853346f8437d92d3c93
        with:
          sarif_file: hd-results.sarif.json
          category: hyperdope
```

Findings appear in the **Security → Code Scanning** tab of your repository.

---

## Threshold configuration

| Threshold | Effect |
|---|---|
| `critical` | Fail only on CVSS 9.0+ |
| `high` | Fail on 7.0+ (default) |
| `medium` | Fail on 4.0+ (strict) |
| `low` | Fail on any known CVE |
| `none` / `info` | Never fail (scan-only mode) |

```yaml
- name: Strict scan (fail on Medium+)
  run: npx hd-ci --target ./ --threshold medium --sarif-out hd-results.sarif.json
```

---

## Scan-only mode (no build failure)

If you want to collect findings without blocking the build:

```yaml
- name: Hyperdope scan (advisory only)
  run: npx hd-ci --target ./ --threshold none --sarif-out hd-results.sarif.json
  # Always exits 0 — never fails the build
```

---

## JSON output for downstream steps

```yaml
- name: Hyperdope scan (JSON)
  id: hd_scan
  run: npx hd-ci --target ./ --json > hd-summary.json || true

- name: Print finding count
  run: |
    COUNT=$(jq '.breaching_findings' hd-summary.json)
    echo "Findings above threshold: $COUNT"
```

---

## Multiple ecosystems in a monorepo

```yaml
- name: Scan backend (Python)
  run: npx hd-ci --target ./backend --sarif-out backend.sarif.json

- name: Scan frontend (npm)
  run: npx hd-ci --target ./frontend --sarif-out frontend.sarif.json

- name: Upload SARIF (backend)
  if: always()
  uses: github/codeql-action/upload-sarif@4dd16135b69a43b6c8efb853346f8437d92d3c93
  with:
    sarif_file: backend.sarif.json
    category: hyperdope-backend

- name: Upload SARIF (frontend)
  if: always()
  uses: github/codeql-action/upload-sarif@4dd16135b69a43b6c8efb853346f8437d92d3c93
  with:
    sarif_file: frontend.sarif.json
    category: hyperdope-frontend
```

---

## Weekly scheduled scan

Catch newly published CVEs for pinned dependency versions:

```yaml
name: Hyperdope Weekly CVE Check

on:
  schedule:
    - cron: '0 8 * * 1'   # every Monday at 08:00 UTC
  workflow_dispatch:       # allow manual trigger

jobs:
  weekly-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      issues: write        # optional: open an issue on new findings

    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: actions/setup-node@39370e3970a6d050c480ffad4ff0ed4d3fdee5af
        with:
          node-version: '20'

      - name: Run weekly scan
        id: scan
        run: |
          npx hd-ci --target ./ --threshold high \
            --sarif-out weekly.sarif.json --json > weekly.json
          echo "exit_code=$?" >> $GITHUB_OUTPUT
        continue-on-error: true

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@4dd16135b69a43b6c8efb853346f8437d92d3c93
        with:
          sarif_file: weekly.sarif.json
          category: hyperdope-weekly

      - name: Open issue on new findings
        if: steps.scan.outputs.exit_code == '1'
        uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea
        with:
          script: |
            const fs = require('fs');
            const summary = JSON.parse(fs.readFileSync('weekly.json', 'utf8'));
            const lines = summary.breaching.map(f =>
              `- **[${f.severity.toUpperCase()}]** ${f.title} (${f.component})`
            ).join('\n');
            github.rest.issues.create({
              owner: context.repo.owner,
              repo:  context.repo.repo,
              title: `[Hyperdope] ${summary.breaching_findings} new vulnerability finding(s)`,
              body:  `## Weekly CVE scan — ${new Date().toISOString().split('T')[0]}\n\n${lines}\n\nSee the [Security tab](../../security/code-scanning) for details.`,
              labels: ['security', 'dependencies'],
            });
```

---

## Notes

- **Pin action SHAs** — use the full 40-character commit SHA for all `uses:` actions, not version tags. Tags can be moved (supply chain attack vector).
- **`security-events: write`** — required for `upload-sarif`. Ensure your workflow has this permission.
- `hd-ci` does not require an LLM API key — it only talks to OSV.dev.
- SARIF results are scoped to the run that produced them; re-runs overwrite previous results in the same `category`.
