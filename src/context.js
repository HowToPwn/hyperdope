const PHASE_BUDGETS = {
  profile:    4000,
  audit:      8000,
  confirm:    6000,
  assess:     4000,
  draft_ghsa: 4000,
  disclose:   6000,
};

// Trim priority: least important first (trimmed first when over budget)
// assess > confirm > audit > profile > draft_ghsa > disclose
// → disclose trimmed first, then draft_ghsa, then profile, audit, confirm, assess last
const TRIM_ORDER = ['disclose', 'draft_ghsa', 'profile', 'audit', 'confirm', 'assess'];

export function estimateTokens(str) {
  if (typeof str !== 'string') return 0;
  return Math.ceil(str.length / 4);
}

export function contextSize(context) {
  if (!context || typeof context !== 'object') return 0;
  return estimateTokens(JSON.stringify(context));
}

function truncateHalf(str) {
  if (typeof str !== 'string') return str;
  const half = Math.floor(str.length / 2);
  return str.slice(0, half) + '\n[...trimmed — see session file for full output]';
}

/**
 * Wrap pipeline data in an XML-style boundary tag so the LLM distinguishes
 * structured phase output from natural-language instructions.
 *
 * Why: the `context` parameter accepted by every Hyperdope MCP tool is
 * caller-supplied and may contain adversarially-crafted strings. Embedding
 * that data verbatim in the user message allows indirect prompt injection —
 * an attacker can place instruction-like text in a prior-phase result (or
 * directly in the `context` argument) that the LLM may follow instead of
 * the built-in system prompt.
 *
 * The `<pipeline_data>` tag signals to the model "this is data to analyze,
 * not instructions to execute". Combined with the security note in each
 * BUILT_IN.system, this raises the bar against indirect injection.
 *
 * The label attribute is controlled by Hyperdope source code, not by callers.
 */
export function wrapDataBlock(label, content) {
  if (content === null || content === undefined || content === '') return '';
  const str = typeof content === 'string' ? content : JSON.stringify(content, null, 2);
  // Escape embedded closing tags so content cannot break out of the boundary.
  // An attacker who controls prior-phase output (e.g. via a malicious repository
  // that the LLM reflects) could otherwise inject "</pipeline_data>" to close the
  // tag early and append instructions that run outside the data block.
  const safe = str.replace(/<\/pipeline_data>/gi, '<\\/pipeline_data>');
  return `<pipeline_data label="${label}">\n${safe}\n</pipeline_data>`;
}

export function trimContext(context, phaseKey) {
  const budget = PHASE_BUDGETS[phaseKey] ?? 6000;
  if (!context || contextSize(context) <= budget) return context;

  const ctx = { ...context };

  for (const field of TRIM_ORDER) {
    if (contextSize(ctx) <= budget) break;
    if (field in ctx && typeof ctx[field] === 'string') {
      ctx[field] = truncateHalf(ctx[field]);
      // If still over after halving, trim again
      if (contextSize(ctx) > budget && ctx[field].length > 200) {
        ctx[field] = truncateHalf(ctx[field]);
      }
    }
  }

  return ctx;
}
