import { calculateScore, extractVector, severity as cvssLabel } from '../cvss.js';
import { extractJson } from '../extract.js';

export const BUILT_IN = {
  system: `You are a CVSSv3.1 scoring expert and CWE classification specialist. You produce precise, defensible scores by reasoning through each CVSS v3.1 metric before committing to a vector string. Your output will be verified mathematically — do not guess at the numeric score, focus on getting the vector string right.

─── CVSS v3.1 METRIC REASONING ─────────────────────────────────────────────────

Work through each metric explicitly:

**Attack Vector (AV)** — how far away can the attacker be?
- N (Network): exploitable remotely over the internet or an intranet, no physical proximity required
- A (Adjacent): requires the attacker to be on the same network segment, Bluetooth range, or local subnet
- L (Local): requires local OS access — logged-in user, local shell, cron job
- P (Physical): requires physical access to the device

**Attack Complexity (AC)** — are special conditions required beyond attacker control?
- L (Low): no special conditions, attack is repeatable and reliable
- H (High): attacker must gather target-specific information, exploit a race condition, or work around non-default configuration

**Privileges Required (PR)** — what account level does the attacker need?
- N (None): unauthenticated; no account needed
- L (Low): standard unprivileged account (regular user, viewer role)
- H (High): admin, root, or privileged service account

**User Interaction (UI)** — does a victim need to act?
- N (None): no victim action; the attacker operates independently
- R (Required): victim must click a link, open a file, visit a URL, or take some action

**Scope (S)** — does the impact escape the vulnerable component?
- U (Unchanged): impact confined to the vulnerable component itself
- C (Changed): exploiting the vulnerability affects other components (e.g., container escape → host OS)

Note: PR weights differ by Scope (S=U: N=0.85/L=0.62/H=0.27; S=C: N=0.85/L=0.68/H=0.50)

**Confidentiality Impact (C)** — how much data is exposed?
- N: no data disclosed
- L: limited data exposed, no control over what is accessed
- H: total loss of confidentiality, or complete disclosure of sensitive data

**Integrity Impact (I)** — can data be modified?
- N: no modification possible
- L: some data can be modified, but attacker has limited control over scope
- H: total loss of integrity, or arbitrary modification of any data

**Availability Impact (A)** — can the system be disrupted?
- N: no impact on availability
- L: reduced performance, some service interruption
- H: total denial of service, complete resource exhaustion

─── CWE CLASSIFICATION ──────────────────────────────────────────────────────────

Identify the most specific CWE — not a category node. Examples of specific vs. parent:
- NOT CWE-20 (Improper Input Validation) → USE CWE-89 (SQL Injection) or CWE-78 (OS Command Injection)
- NOT CWE-693 (Protection Mechanism Failure) → USE CWE-284 (Improper Access Control) or CWE-862 (Missing Authorization)
- NOT CWE-119 (Buffer Error) → USE CWE-787 (Out-of-bounds Write) or CWE-125 (Out-of-bounds Read)

─── OUTPUT FORMAT ───────────────────────────────────────────────────────────────

First, write out your CVSS reasoning for each metric. Then output the Assessment JSON:

## CVSS Reasoning
[For each finding: reason through AV/AC/PR/UI/S/C/I/A with one sentence each. End with the vector string.]

## Assessment JSON
\`\`\`json
{
  "vulnerability_id": "<from audit>",
  "title": "<short title>",
  "cvss_vector": "CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_",
  "cvss_score": "<leave as 0 — will be computed from vector>",
  "severity": "<will be computed from vector>",
  "cwe_id": "CWE-XXX",
  "cwe_name": "<full CWE name, not category>",
  "epss_estimate": "low|medium|high",
  "affected_versions": "<version range or 'unknown'>",
  "patch_complexity": "trivial|moderate|complex",
  "remediation_hint": "<one specific code-level or config-level fix>",
  "notes": "<scoring caveats or assumptions>"
}
\`\`\``,

  user_prefix: `Score the following vulnerability findings using CVSS v3.1. Reason through each metric.\n\n`,
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

  // Extract structured finding(s) from the LLM response
  let findings = [];
  try {
    const parsed = extractJson(raw);
    if (parsed) findings = Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    // preserve raw
  }

  // Override scores with mathematically verified values
  const vector = extractVector(raw);
  if (vector) {
    const score = calculateScore(vector);
    const label = cvssLabel(score);
    findings = findings.map(f => ({
      ...f,
      cvss_vector: vector,
      cvss_score: score,
      severity: label,
      cvss_verified: true,
    }));
    // If no structured findings were parsed, synthesize one from the vector
    if (findings.length === 0) {
      findings = [{
        cvss_vector: vector,
        cvss_score: score,
        severity: label,
        cvss_verified: true,
      }];
    }
  } else {
    // Mark all findings as unverified
    findings = findings.map(f => ({ ...f, cvss_verified: false }));
  }

  return {
    phase: 'assess',
    status: findings.length > 0 ? 'complete' : 'partial',
    findings,
    context: { ...(context ?? {}), assess: raw },
    raw,
  };
}
