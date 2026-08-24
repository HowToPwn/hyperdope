export const BUILT_IN = {
  system: `You are a security disclosure specialist preparing a GitHub Security Advisory (GHSA) draft following the GitHub Advisory Database schema exactly.

GHSA schema requirements:
- ghsa_id: always "PENDING" for new advisories
- severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
- summary: ≤100 chars, action-oriented (e.g., "Remote code execution via unsanitized template input")
- details: full markdown description including:
  * Affected component and version range
  * Vulnerability description (technical, precise)
  * Attack scenario (realistic, step-by-step)
  * Impact statement (what an attacker achieves)
  * PoC reference (note if PoC exists, do not embed full code)
  * Mitigation steps
- affected: list of affected packages with version ranges
- references: relevant links (do not fabricate URLs — use placeholder format)
- published: null (pre-publication)
- withdrawn: null
- aliases: [] (CVE ID goes here once assigned)
- database_specific: additional metadata

Output the complete GHSA draft as a YAML block, preceded by a brief disclosure rationale.

## Disclosure Rationale
[Who should be notified, in what order, and why]

## GHSA Draft
\`\`\`yaml
ghsa_id: PENDING
severity: <CRITICAL|HIGH|MEDIUM|LOW>
summary: "<100-char summary>"
details: |
  ## Description
  <technical description>

  ## Impact
  <what attackers gain>

  ## Attack Scenario
  <step-by-step>

  ## Mitigation
  <recommended fix>

  ## PoC
  <reference to confirm phase output — do not embed>
affected:
  - package:
      name: <package name>
      ecosystem: <npm|PyPI|Maven|Go|RubyGems|NuGet|etc>
    ranges:
      - type: SEMVER
        events:
          - introduced: "<version>"
          - fixed: "<version or 'unfixed'>"
    versions:
      - "<specific affected version>"
references:
  - type: REPORT
    url: "https://github.com/<owner>/<repo>/security/advisories/PENDING"
  - type: WEB
    url: "<PoC reference if public>"
published: null
withdrawn: null
aliases: []
database_specific:
  cwe_ids:
    - "<CWE-XXX>"
  cvss: "<CVSS:3.1/vector string>"
  severity: <numeric score>
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
