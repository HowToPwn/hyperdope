// ── Safe fenced block extraction ─────────────────────────────────────────────
//
// Uses pure indexOf — O(n), zero regex backtracking, safe on uncontrolled input.
// CodeQL CWE-1333 requires that patterns applied to user-controlled strings be
// linear. Replacing /```json\s*([\s\S]*?)```/ with indexOf removes all
// backtracking risk while producing identical results.

/**
 * Extract the content between a fenced code block pair.
 *
 * Accepts an optional language tag (e.g. "json") and returns the trimmed
 * content between the opening fence (`\`\`\`json`) and the first closing
 * fence (`\`\`\``), or null if no complete pair is found.
 *
 * Complexity: O(n) — no regex, no backtracking.
 *
 * @param {string} raw  — The full text to search.
 * @param {string} lang — Optional language tag after the opening fence.
 * @returns {string|null}
 */
function extractFenced(raw, lang = '') {
  const needle = '```' + lang;

  const openIdx = raw.indexOf(needle);
  if (openIdx === -1) return null;

  // Skip to the end of the opening line so we don't confuse
  // "```json" with "```javascript" when lang === "json".
  const afterNeedle = openIdx + needle.length;
  const lineBreak   = raw.indexOf('\n', afterNeedle);
  if (lineBreak === -1) return null;

  const contentStart = lineBreak + 1;

  // Closing fence — first ``` that appears after the content start
  const closeIdx = raw.indexOf('```', contentStart);
  if (closeIdx === -1) return null;

  return raw.slice(contentStart, closeIdx).trim();
}

// ── Balanced brace extraction ─────────────────────────────────────────────────
//
// Handles nested objects and escaped strings.
// O(n) single-pass — no regex involved.

function extractBalancedObject(raw) {
  const start = raw.indexOf('{');
  if (start === -1) return null;

  let depth    = 0;
  let inString = false;
  let escape   = false;

  for (let i = start; i < raw.length; i++) {
    const ch = raw[i];

    if (escape)               { escape = false; continue; }
    if (ch === '\\' && inString) { escape = true;  continue; }
    if (ch === '"')           { inString = !inString; continue; }
    if (inString)             continue;

    if (ch === '{') { depth++; }
    else if (ch === '}') {
      depth--;
      if (depth === 0) return raw.slice(start, i + 1);
    }
  }

  return null;
}

// ── Public API ────────────────────────────────────────────────────────────────

export function extractJson(raw) {
  if (!raw || typeof raw !== 'string') return null;

  // 1. Fenced ```json block (language-tagged)
  const fromJson = extractFenced(raw, 'json');
  if (fromJson !== null) {
    try { return JSON.parse(fromJson); } catch { /* fall through */ }
  }

  // 2. Fenced ``` block (no language tag)
  const fromPlain = extractFenced(raw, '');
  if (fromPlain !== null) {
    try { return JSON.parse(fromPlain); } catch { /* fall through */ }
  }

  // 3. Brace-counted extraction (handles JSON embedded in free text)
  const balanced = extractBalancedObject(raw);
  if (balanced) {
    try { return JSON.parse(balanced); } catch { /* fall through */ }
  }

  return null;
}

export function extractJsonArray(raw) {
  if (!raw || typeof raw !== 'string') return [];

  // 1. Fenced ```json block
  const fromJson = extractFenced(raw, 'json');
  if (fromJson !== null) {
    try {
      const parsed = JSON.parse(fromJson);
      if (Array.isArray(parsed)) return parsed;
      for (const key of ['findings', 'results', 'items', 'vulns', 'vulnerabilities']) {
        if (Array.isArray(parsed[key])) return parsed[key];
      }
      return [parsed];
    } catch { /* fall through */ }
  }

  // 2. Check for a top-level array before object
  const arrStart = raw.indexOf('[');
  const objStart = raw.indexOf('{');
  if (arrStart !== -1 && (objStart === -1 || arrStart < objStart)) {
    try {
      const end = raw.lastIndexOf(']');
      if (end > arrStart) return JSON.parse(raw.slice(arrStart, end + 1));
    } catch { /* fall through */ }
  }

  // 3. Fall back to object extraction + look for array fields
  const obj = extractJson(raw);
  if (!obj) return [];
  if (Array.isArray(obj)) return obj;
  for (const key of ['findings', 'results', 'items', 'vulns', 'vulnerabilities', 'surface_categories']) {
    if (Array.isArray(obj[key])) return obj[key];
  }
  return [obj];
}
