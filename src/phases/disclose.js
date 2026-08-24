export const BUILT_IN = {
  system: `You are a security communications specialist producing the final coordinated disclosure package. You produce three distinct outputs in a single response.

**Output A — Executive Brief (2 paragraphs, non-technical)**
Written for: CISO, VP Engineering, Board-level stakeholders
Requirements:
- No CVE IDs, no CWE numbers, no CVSS vectors in this section
- Plain business language: what is at risk, who is affected, what action is required
- Paragraph 1: the problem and its business impact
- Paragraph 2: recommended response and timeline
- Tone: calm, factual, actionable — not alarmist

**Output B — Full Technical Advisory**
Written for: security engineers, developers, incident responders
Requirements:
- Vulnerability title, CVSS score, severity, CWE
- Affected component: file, function, version range
- Root cause: precise technical explanation, reference to the vulnerable code pattern
- Attack scenario: step-by-step, referencing the PoC
- Impact: what is achievable (RCE, data exfil, auth bypass, etc.), blast radius
- Detection: log entries, anomaly patterns, indicators of compromise
- Remediation: specific code change, configuration fix, or workaround
- Timeline: [discovery date: TBD], [vendor notification: TBD], [publication: TBD]

**Output C — Vendor Notification Email Template**
Written for: the vendor's security team / responsible disclosure inbox
Requirements:
- Subject line (informative but not sensational)
- Professional, collegial tone — assume good faith
- Summary of the vulnerability (2-3 sentences)
- CVSS score and vector
- Reference to PoC (offer to share under embargo)
- Proposed 90-day disclosure timeline (from notification date)
- Contact information placeholder
- Do not include full PoC code in the email

Format your response with these exact headers:
---
## A. Executive Brief
[content]

---
## B. Technical Advisory
[content]

---
## C. Vendor Notification Template
[content]
---`,

  user_prefix: `Produce the complete disclosure package for the following security finding:\n\n`,
};

export async function runDisclose({ config, target, context, callProvider, phaseConfig }) {
  const system = phaseConfig?.system ?? BUILT_IN.system;
  const userPrefix = phaseConfig?.user_prefix ?? BUILT_IN.user_prefix;

  const sections = [];

  if (context?.assess) sections.push(`CVSS Assessment:\n${context.assess}`);
  if (context?.draft_ghsa) sections.push(`GHSA Draft:\n${context.draft_ghsa}`);
  if (context?.confirm) sections.push(`PoC:\n${context.confirm}`);
  if (context?.audit) sections.push(`Audit Findings:\n${context.audit}`);
  if (!sections.length) sections.push(`Target: ${target}`);

  const user = `${userPrefix}${sections.join('\n\n')}`;

  const raw = await callProvider(config, { system, user });

  const execBrief = raw.match(/## A\. Executive Brief([\s\S]*?)(?=## B\.|$)/)?.[1]?.trim() ?? '';
  const techAdvisory = raw.match(/## B\. Technical Advisory([\s\S]*?)(?=## C\.|$)/)?.[1]?.trim() ?? '';
  // Vendor email is the last section — take everything after the header to end of string
  const vendorEmail = raw.match(/## C\. Vendor Notification Template([\s\S]*)/)?.[1]?.trim() ?? '';

  return {
    phase: 'disclose',
    status: 'complete',
    findings: [
      { type: 'executive_brief', content: execBrief },
      { type: 'technical_advisory', content: techAdvisory },
      { type: 'vendor_email_template', content: vendorEmail },
    ],
    context: { ...(context ?? {}), disclose: raw },
    raw,
  };
}
