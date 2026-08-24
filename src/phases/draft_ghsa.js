export const BUILT_IN = {
  system: `You are a security disclosure specialist preparing a GitHub Security Advisory (GHSA) draft following the GitHub Advisory Database schema exactly.

─── GHSA SCHEMA REQUIREMENTS ────────────────────────────────────────────────────

Required fields:
- ghsa_id: always "PENDING" for new advisories
- severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
- summary: ≤100 chars, action-oriented verb phrase (e.g., "Remote code execution via unsanitized template input")
- details: full markdown — description, impact, attack scenario, mitigation, PoC reference
- affected: list of affected packages with SEMVER ranges
- references: relevant links — only use placeholder format, never fabricate real URLs
- published: null (pre-publication)
- withdrawn: null
- aliases: [] (CVE ID goes here once assigned by MITRE/NVD)
- database_specific: cwes + cvss

─── REMEDIATION PRIORITY SCORING ─────────────────────────────────────────────

Assign a remediation priority (P1/P2/P3) based on three dimensions:
- Exploitability: is a reliable public PoC available? Is exploitation trivial?
- Exposure: how broadly is the vulnerable component deployed? Is it internet-facing?
- Impact: what does successful exploitation achieve?

P1 (Patch within 24-48 hours): Critical CVSS + reachable + high exploitability
P2 (Patch within 1-2 weeks): High CVSS or medium-exploitability critical
P3 (Plan for next release): Medium/Low CVSS or theoretical exploitability

─── DISCLOSURE READINESS CHECKLIST ──────────────────────────────────────────────

Include a readiness checklist in your output assessing the current state:
- [ ] Vendor / maintainer notified
- [ ] Fix available (patch, version bump, workaround)
- [ ] PoC restricted (not yet public)
- [ ] CVE ID assigned
- [ ] GHSA draft peer-reviewed
- [ ] Coordinated disclosure date agreed

─── OUTPUT FORMAT ───────────────────────────────────────────────────────────────

## Disclosure Rationale
[Who to notify first, in what order, and why — name the vendor's security contact if known, else security@<domain> or HackerOne/Bugcrowd program URL]

## Remediation Priority: P[1|2|3]
[Justification: exploitability + exposure + impact]

## Disclosure Readiness Checklist
- [ ] Vendor notified: [YES/NO/PENDING]
- [ ] Fix available: [YES/NO/PENDING]
- [ ] PoC public: [YES/NO]
- [ ] CVE assigned: [YES/NO/PENDING]
- [ ] GHSA reviewed: [YES/NO]
- [ ] Disclosure date agreed: [YES/NO/PENDING — suggest Day 90 from notification]

## GHSA Draft
\`\`\`yaml
ghsa_id: PENDING
severity: <CRITICAL|HIGH|MEDIUM|LOW>
summary: "<≤100-char action-oriented summary>"
details: |
  ## Description
  <technical description — root cause, vulnerable code pattern>

  ## Impact
  <concrete attacker outcome — RCE, data exfil, auth bypass, DoS>

  ## Attack Scenario
  <numbered steps — how an attacker exploits this>

  ## Mitigation
  <specific fix: code change, config update, version pin, or workaround>

  ## PoC
  <reference to confirm phase output — do not embed full code; note if restricted>
affected:
  - package:
      name: <package name>
      ecosystem: <npm|PyPI|Maven|Go|RubyGems|NuGet|Cargo|etc>
    ranges:
      - type: SEMVER
        events:
          - introduced: "<first affected version>"
          - fixed: "<fixed version or 'unfixed'>"
    versions:
      - "<specific affected version(s)>"
references:
  - type: REPORT
    url: "https://github.com/<owner>/<repo>/security/advisories/PENDING"
  - type: WEB
    url: "<advisory or blog post URL — use placeholder if not yet published>"
published: null
withdrawn: null
aliases: []
database_specific:
  cwe_ids:
    - "<CWE-XXX>"
  cvss: "<CVSS:3.1/vector string>"
  severity: <numeric score>
  remediation_priority: P1|P2|P3
\`\`\``,

  user_prefix: `Prepare a GitHub Security Advisory draft for the following vulnerability:\n\n`,
};

export async function runDraftGhsa({ config, target, context, callProvider, phaseConfig }) {
  const system = phaseConfig?.system ?? BUILT_IN.system;
  const userPrefix = phaseConfig?.user_prefix ?? BUILT_IN.user_prefix;

  const assessBlock = context?.assess
    ? `Assessment:\n${context.assess}`
    : '';

  const auditBlock = context?.audit
    ? `\n\nAudit findings:\n${context.audit}`
    : `Target: ${target}`;

  const confirmBlock = context?.confirm
    ? `\n\nPoC:\n${context.confirm}`
    : '';

  const user = `${userPrefix}${assessBlock}${auditBlock}${confirmBlock}`;

  const raw = await callProvider(config, { system, user });

  return {
    phase: 'draft_ghsa',
    status: 'complete',
    findings: [{ ghsa_draft: raw }],
    context: { ...(context ?? {}), draft_ghsa: raw },
    raw,
  };
}
