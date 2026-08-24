export const BUILT_IN = {
  system: `You are a CVSSv3.1 scoring expert and CWE classification specialist. You score vulnerabilities with precision, using chain-of-thought reasoning before committing to a numeric score.

CVSS v3.1 metric reasoning process — work through each metric before scoring:

**Attack Vector (AV)**: Network (N) / Adjacent (A) / Local (L) / Physical (P)
- N: exploitable remotely over internet/intranet
- A: requires attacker on same network segment
- L: requires local access (logged-in user)
- P: requires physical device access

**Attack Complexity (AC)**: Low (L) / High (H)
- L: no special conditions, repeatable
- H: requires specific race condition, configuration, or non-default state

**Privileges Required (PR)**: None (N) / Low (L) / High (H)
- N: unauthenticated attacker
- L: normal user account
- H: admin/root

**User Interaction (UI)**: None (N) / Required (R)
- N: no victim action needed
- R: victim must click, visit, or act

**Scope (S)**: Unchanged (U) / Changed (C)
- U: impact confined to vulnerable component
- C: impact spreads to other components/systems

**Confidentiality Impact (C)**: None (N) / Low (L) / High (H)
**Integrity Impact (I)**: None (N) / Low (L) / High (H)
**Availability Impact (A)**: None (N) / Low (L) / High (H)

Severity thresholds:
- Critical: 9.0–10.0
- High: 7.0–8.9
- Medium: 4.0–6.9
- Low: 0.1–3.9
- None: 0.0

CWE classification: identify the most specific applicable CWE, not a parent category.

Output format — reason first, then JSON:

## CVSS Reasoning
[Walk through each metric with justification]

## Assessment JSON
\`\`\`json
{
  "vulnerability_id": "<from audit>",
  "title": "<short title>",
  "cvss_vector": "CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_",
  "cvss_score": <numeric 0.0-10.0>,
  "severity": "Critical|High|Medium|Low|None",
  "cwe_id": "CWE-XXX",
  "cwe_name": "<full CWE name>",
  "exploitability_subscore": <0.0-3.9>,
  "impact_subscore": <0.0-6.0>,
  "epss_estimate": "<low|medium|high — estimated probability of exploitation in the wild>",
  "affected_versions": "<version range or 'unknown'>",
  "patch_complexity": "trivial|moderate|complex",
  "notes": "<any scoring caveats or assumptions>"
}
\`\`\``,

  user_prefix: `Score the following vulnerability finding using CVSS v3.1 and classify its CWE:\n\n`,
};

export async function runAssess({ config, target, context, callProvider, phaseConfig }) {
  const system = phaseConfig?.system ?? BUILT_IN.system;
  const userPrefix = phaseConfig?.user_prefix ?? BUILT_IN.user_prefix;

  const findingBlock = context?.audit
    ? `Audit findings:\n${context.audit}`
    : `Target: ${target}`;

  const confirmBlock = context?.confirm
    ? `\n\nPoC confirmation:\n${context.confirm}`
    : '';

  const user = `${userPrefix}${findingBlock}${confirmBlock}`;

  const raw = await callProvider(config, { system, user });

  let findings = [];
  try {
    // prefer fenced code block; fall back to bare JSON object
    const fenced = raw.match(/```json\s*([\s\S]*?)```/);
    const bare = raw.match(/\{[\s\S]*\}/);
    const src = fenced ? fenced[1].trim() : bare ? bare[0] : null;
    if (src) {
      const parsed = JSON.parse(src);
      findings = Array.isArray(parsed) ? parsed : [parsed];
    }
  } catch {
    // preserve raw
  }

  return {
    phase: 'assess',
    status: findings.length > 0 ? 'complete' : 'partial',
    findings,
    context: { ...(context ?? {}), assess: raw },
    raw,
  };
}
