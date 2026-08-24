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
