import { z } from 'zod';

// ── Enum primitives ───────────────────────────────────────────────────────────

export const SeverityLevel = z.enum(['critical', 'high', 'medium', 'low', 'info', 'none']);
export const FindingStatus  = z.enum(['open', 'confirmed', 'patched', 'wont_fix', 'disputed']);
export const PhaseEnum      = z.enum([
  'scan', 'profile', 'audit', 'confirm', 'assess',
  'draft_ghsa', 'disclose', 'verify',
]);

// ── Canonical finding schema ──────────────────────────────────────────────────

/**
 * HyperFinding — the stable output contract for all Hyperdope phases.
 *
 * Every phase result now carries a `normalized_findings` array conforming to
 * this schema so downstream tools (CI exit gates, SARIF exporters, custom
 * pipelines) have a reliable interface regardless of which phase produced the
 * findings.
 *
 * The raw, phase-specific `findings` array is preserved alongside it for
 * backwards compatibility.
 */
export const HyperFindingSchema = z.object({
  id:          z.string(),
  phase:       PhaseEnum,
  title:       z.string(),
  cwe_id:      z.string().optional(),
  cvss_vector: z.string().optional(),
  cvss_score:  z.number().min(0).max(10).optional(),
  severity:    SeverityLevel,
  component:   z.string().optional(),
  description: z.string(),
  evidence:    z.string().optional(),
  poc:         z.string().optional(),
  status:      FindingStatus.default('open'),
  tags:        z.array(z.string()).default([]),

  /**
   * Evidence-quality confidence tier (1–5).
   * Computed programmatically from observable evidence — not self-reported by LLM.
   *
   *   5 = CONFIRMED   — file path + line + PoC + CVSS verified + chain ≤ 3 hops
   *   4 = HIGH        — 4 of 5 criteria met
   *   3 = MEDIUM      — 3 of 5 criteria met
   *   2 = LOW         — only 2 criteria met
   *   1 = SPECULATIVE — pattern matched, chain unverified
   */
  confidence: z.number().int().min(1).max(5).optional(),

  /**
   * Blast radius context — populated by the scan phase for CVE findings.
   * Gives downstream consumers a sense of how many deployments are at risk.
   */
  blast_radius: z.object({
    monthly_downloads: z.number().optional(),
    tier: z.enum(['massive', 'high', 'medium', 'low']).optional(),
    source: z.string().optional(),    // 'npm' | 'pypi'
  }).optional(),

  /**
   * Chain elevation note — set when this finding pairs with another to
   * produce a higher-severity chain (e.g. path-traversal + config-write = RCE).
   * Value is a human-readable description of the chain.
   */
  chain_elevation: z.string().optional(),
});

// ── Severity coercion ─────────────────────────────────────────────────────────

/** Map any free-form severity string or numeric score to a SeverityLevel. */
export function normalizeSeverity(raw) {
  if (raw === null || raw === undefined) return 'info';
  const s = String(raw).toLowerCase();
  if (s.includes('critical'))                  return 'critical';
  if (s.includes('high'))                      return 'high';
  if (s.includes('medium') || s.includes('moderate')) return 'medium';
  if (s.includes('low'))                       return 'low';
  if (s.includes('none') || s === '0' || s === '0.0') return 'none';
  // Numeric CVSS score embedded in an OSV severity string
  const num = parseFloat(s);
  if (!isNaN(num)) {
    if (num >= 9.0) return 'critical';
    if (num >= 7.0) return 'high';
    if (num >= 4.0) return 'medium';
    if (num >  0)   return 'low';
    return 'none';
  }
  return 'info';
}

// ── Phase-specific normalization ──────────────────────────────────────────────

/**
 * Convert a raw phase-specific finding object into a HyperFinding.
 * Each phase returns a different shape; this fan-out normalizes all of them.
 */
export function normalizeFinding(raw, phase, idx = 0) {
  const id   = raw?.id ?? `${phase.toUpperCase()}-${String(idx + 1).padStart(3, '0')}`;
  const base = { id, phase, status: 'open', tags: [] };

  switch (phase) {
    case 'scan':
      return {
        ...base,
        title:       raw.summary ?? raw.osv_id ?? id,
        cwe_id:      undefined,
        cvss_vector: undefined,
        cvss_score:  undefined,
        severity:    normalizeSeverity(raw.severity),
        component:   `${raw.ecosystem}:${raw.package}@${raw.version}`,
        description: raw.summary ?? '',
        evidence:    [...(raw.aliases ?? []), raw.osv_id].filter(Boolean).join(', '),
        tags:        [raw.ecosystem ?? 'unknown'],
      };

    case 'secret':
      return {
        ...base,
        id:          raw.id ?? `SECRET-${String(idx + 1).padStart(3, '0')}`,
        title:       `Hardcoded secret: ${raw.type}`,
        cwe_id:      'CWE-798',
        severity:    'high',
        component:   raw.file,
        description: `Potential hardcoded credential of type "${raw.type}" detected.`,
        evidence:    raw.match_preview,
        tags:        ['secret', 'credentials'],
      };

    case 'profile':
      return {
        ...base,
        title:       `${raw.category ?? id} attack surface`,
        severity:    normalizeSeverity(raw.priority),
        component:   raw.evidence,
        description: raw.description ?? '',
        evidence:    (raw.attack_vectors ?? []).join('; '),
        tags:        raw.stride_applicable ?? [],
      };

    case 'audit':
      return {
        ...base,
        title:       raw.title ?? id,
        cwe_id:      raw.cwe_id,
        severity:    normalizeSeverity(raw.severity_estimate ?? raw.severity),
        component:   raw.affected_component,
        description: raw.description ?? raw.attack_scenario ?? '',
        evidence:    raw.evidence,
        tags:        [raw.vulnerability_class, raw.surface_category].filter(Boolean),
      };

    case 'assess':
      return {
        ...base,
        id:          raw.vulnerability_id ?? id,
        title:       raw.title ?? id,
        cwe_id:      raw.cwe_id,
        cvss_vector: raw.cvss_vector,
        cvss_score:  typeof raw.cvss_score === 'number' ? raw.cvss_score : undefined,
        severity:    normalizeSeverity(raw.severity ?? raw.cvss_score),
        component:   raw.affected_component,
        description: raw.notes ?? '',
        tags:        raw.cvss_verified ? ['cvss-verified'] : ['cvss-unverified'],
      };

    case 'verify':
      return {
        ...base,
        id:          raw.finding_id ?? id,
        title:       raw.original_title ?? id,
        severity:    normalizeSeverity(raw.remaining_risk),
        description: raw.reasoning ?? '',
        status:      { PATCHED: 'patched', STILL_VULNERABLE: 'confirmed',
                       PARTIAL_FIX: 'confirmed', CANNOT_VERIFY: 'open' }[raw.verdict] ?? 'open',
        tags:        [raw.verdict?.toLowerCase() ?? 'unverified'],
      };

    default:
      return {
        ...base,
        title:       raw.title ?? raw.type ?? id,
        severity:    normalizeSeverity(raw.severity ?? raw.severity_estimate),
        description: raw.content ?? raw.description ?? raw.poc ??
                     JSON.stringify(raw).slice(0, 200),
      };
  }
}

/** Normalize all findings from a phase result into HyperFinding[] */
export function normalizeFindings(findings, phase) {
  if (!Array.isArray(findings)) return [];
  return findings.map((f, i) => {
    const normalized = normalizeFinding(f, phase, i);
    // Attach computed confidence score and blast radius if present in raw finding
    normalized.confidence   = computeConfidence({ ...f, ...normalized });
    if (f.blast_radius) normalized.blast_radius   = f.blast_radius;
    if (f.chain_elevation) normalized.chain_elevation = f.chain_elevation;
    return normalized;
  });
}

// ── Confidence scoring ────────────────────────────────────────────────────────

/**
 * Compute an evidence-quality confidence score (1–5) for a finding.
 * Purely programmatic — examines the fields present on the finding object.
 * Does NOT ask the LLM; this is the anti-hallucination guard.
 *
 * Criteria (each worth 1 point):
 *   1. Specific file path cited  (component or file field contains '.')
 *   2. Specific line number cited (component contains ':<digits>' or line field set)
 *   3. PoC is deterministic       (poc field present, or reliability === 'deterministic')
 *   4. CVSS mathematically verified (cvss_verified === true or tags includes 'cvss-verified')
 *   5. Chain depth ≤ 3 hops       (chain_hops unset/≤3; unset = single-hop = safe)
 *
 * @param {object} finding — raw or normalized finding object
 * @returns {1|2|3|4|5}
 */
export function computeConfidence(finding) {
  let score = 0;

  // 1. Specific file reference
  const comp = finding.component ?? finding.file ?? '';
  if (comp && /\.[a-z]{1,5}(:|$)/i.test(comp)) score++;

  // 2. Line number
  if (finding.line || /:\d+$/.test(comp)) score++;

  // 3. PoC or deterministic verification
  if (finding.poc || finding.reliability === 'deterministic' ||
      (typeof finding.evidence === 'string' && /\bpoc\b|proof.of.concept/i.test(finding.evidence))) {
    score++;
  }

  // 4. CVSS mathematically verified
  if (finding.cvss_verified === true ||
      (Array.isArray(finding.tags) && finding.tags.includes('cvss-verified'))) {
    score++;
  }

  // 5. Chain depth acceptable (no unverified long hops)
  if (!finding.chain_hops || finding.chain_hops <= 3) score++;

  return /** @type {1|2|3|4|5} */ (Math.min(5, Math.max(1, score)));
}

export const CONFIDENCE_LABELS = /** @type {Record<number,string>} */ ({
  5: 'CONFIRMED',
  4: 'HIGH',
  3: 'MEDIUM',
  2: 'LOW',
  1: 'SPECULATIVE',
});

// ── SARIF 2.1.0 export ────────────────────────────────────────────────────────

/**
 * Convert HyperFinding[] to SARIF 2.1.0 format.
 * Used by `hd-ci` for GitHub Code Scanning integration.
 */
export function exportSarif(findings, { tool = 'hyperdope', version = '0.3.0' } = {}) {
  const sarifLevel = { critical: 'error', high: 'error', medium: 'warning',
                       low: 'note', info: 'none', none: 'none' };

  // Deduplicate rules by CWE or phase
  const rulesMap = new Map();
  for (const f of findings) {
    const ruleId = f.cwe_id ?? `HD-${f.phase.toUpperCase()}`;
    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id:   ruleId,
        name: (f.cwe_id ? `${f.cwe_id.replace('-', '')}` : `Hyperdope${f.phase}`)
                .replace(/[^A-Za-z0-9]/g, '').slice(0, 60),
        shortDescription:    { text: f.cwe_id ? `${f.cwe_id} — ${f.title}` : f.title },
        defaultConfiguration: { level: sarifLevel[f.severity] ?? 'warning' },
        properties:           { tags: ['security', ...(f.tags ?? [])] },
      });
    }
  }

  const results = findings.map(f => {
    const ruleId                  = f.cwe_id ?? `HD-${f.phase.toUpperCase()}`;
    const [filePart, linePart]    = (f.component ?? '').split(':');
    const line                    = parseInt(linePart, 10) || 1;
    return {
      ruleId,
      level:   sarifLevel[f.severity] ?? 'warning',
      message: { text: f.description || f.title },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: filePart || f.component || 'unknown' },
          region:           { startLine: line },
        },
      }],
      properties: {
        severity:    f.severity,
        cvss_vector: f.cvss_vector,
        cvss_score:  f.cvss_score,
        status:      f.status,
        phase:       f.phase,
      },
    };
  });

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name:           tool,
          version,
          informationUri: 'https://github.com/HowToPwn/hyperdope',
          rules:          [...rulesMap.values()],
        },
      },
      results,
    }],
  };
}
