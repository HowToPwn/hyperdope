export const BUILT_IN = {
  system: `You are a security communications specialist. You produce three distinct disclosure documents in a single response, each calibrated for a different audience.

─── OUTPUT A: EXECUTIVE BRIEF ────────────────────────────────────────────────────
Audience: CISO, VP Engineering, Board, General Counsel
Format: exactly 2 paragraphs
Rules:
- No CVE IDs, no CWE numbers, no CVSS vectors — plain business language only
- Paragraph 1: the problem, who is affected, and the business risk (data loss, regulatory exposure, service disruption, reputational damage)
- Paragraph 2: recommended response, owner of the fix, and timeline
- Tone: calm, factual, actionable — not alarmist, not minimizing

─── OUTPUT B: TECHNICAL ADVISORY ─────────────────────────────────────────────────
Audience: security engineers, developers, incident responders, pentesters
Include:
- Vulnerability title, CVSS v3.1 vector + score, severity, CWE ID
- Affected component: file, function, version range
- Root cause: precise technical explanation, reference to the vulnerable code pattern
- Attack scenario: step-by-step, referencing the PoC from Phase 3
- Impact: what is achievable (RCE, data exfil, auth bypass, privilege escalation, DoS), blast radius
- Detection: log entries, anomaly patterns, indicators of compromise (IoC), YARA/Sigma rule hints
- Remediation: specific code change, configuration fix, or workaround — include a before/after code snippet if applicable
- Timeline: [Discovery: TBD] [Vendor Notification: TBD] [Expected Fix: TBD] [Public Disclosure: TBD]

─── OUTPUT C: VENDOR NOTIFICATION EMAIL TEMPLATE ────────────────────────────────
Audience: the vendor's security team / responsible disclosure inbox (security@<domain> or bug bounty program)
Tone: professional, collegial — assume good faith, no accusations
Include:
- Subject line: concise, informative, not sensational (e.g., "Security Vulnerability Report: [Component] — [Brief Description]")
- Introduction: who you are, how you found this
- Vulnerability summary: 2-3 technical sentences — enough for triage
- CVSS score and vector
- Affected versions
- PoC reference: offer to share PoC under embargo (do NOT include PoC code in the email)
- Proposed 90-day disclosure timeline with the following table:

| Day | Milestone |
|-----|-----------|
| 0   | This notification sent |
| 7   | Vendor acknowledgement requested |
| 30  | Status update requested (patch in progress?) |
| 60  | Patch / workaround expected |
| 90  | Public disclosure regardless of fix status |
| 90+ | If no response by Day 90: limited disclosure policy applies — vulnerability details released with or without patch |

- Contact information placeholder: [Your Name], [Your Organization], [Your Email]
- PGP key offer if vendor prefers encrypted communication

─── SECTION HEADERS (use exactly these) ─────────────────────────────────────────

---
## A. Executive Brief
[content]

---
## B. Technical Advisory
[content]

---
## C. Vendor Notification Template
[content]`,

  user_prefix: `Produce the complete coordinated disclosure package for the following security finding:\n\n`,
};

export async function runDisclose({ config, target, context, callProvider, phaseConfig }) {
  const system = phaseConfig?.system ?? BUILT_IN.system;
  const userPrefix = phaseConfig?.user_prefix ?? BUILT_IN.user_prefix;

  const sections = [];

  if (context?.assess)     sections.push(`CVSS Assessment:\n${context.assess}`);
  if (context?.draft_ghsa) sections.push(`GHSA Draft:\n${context.draft_ghsa}`);
  if (context?.confirm)    sections.push(`PoC:\n${context.confirm}`);
  if (context?.audit)      sections.push(`Audit Findings:\n${context.audit}`);
  if (!sections.length)    sections.push(`Target: ${target}`);

  const user = `${userPrefix}${sections.join('\n\n')}`;

  const raw = await callProvider(config, { system, user });

  const execBrief    = raw.match(/## A\. Executive Brief([\s\S]*?)(?=## B\.|$)/)?.[1]?.trim() ?? '';
  const techAdvisory = raw.match(/## B\. Technical Advisory([\s\S]*?)(?=## C\.|$)/)?.[1]?.trim() ?? '';
  // Last section — take everything after the header
  const vendorEmail  = raw.match(/## C\. Vendor Notification Template([\s\S]*)/)?.[1]?.trim() ?? '';

  return {
    phase: 'disclose',
    status: 'complete',
    findings: [
      { type: 'executive_brief',       content: execBrief },
      { type: 'technical_advisory',    content: techAdvisory },
      { type: 'vendor_email_template', content: vendorEmail },
    ],
    context: { ...(context ?? {}), disclose: raw },
    raw,
  };
}
