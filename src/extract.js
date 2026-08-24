// Balanced brace extraction — handles nested objects and escaped strings.
function extractBalancedObject(raw) {
  const start = raw.indexOf('{');
  if (start === -1) return null;

  let depth = 0;
  let inString = false;
  let escape = false;

  for (let i = start; i < raw.length; i++) {
    const ch = raw[i];

    if (escape) {
      escape = false;
      continue;
    }

    if (ch === '\\' && inString) {
      escape = true;
      continue;
    }

    if (ch === '"') {
      inString = !inString;
      continue;
    }

    if (inString) continue;

    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) {
        return raw.slice(start, i + 1);
      }
    }
  }

  return null;
}

export function extractJson(raw) {
  if (!raw || typeof raw !== 'string') return null;

  // 1. Fenced ```json block
  const fencedJson = raw.match(/```json\s*([\s\S]*?)```/);
  if (fencedJson) {
    try { return JSON.parse(fencedJson[1].trim()); } catch { /* fall through */ }
  }

  // 2. Fenced ``` block (no language)
  const fencedPlain = raw.match(/```\s*([\s\S]*?)```/);
  if (fencedPlain) {
    try { return JSON.parse(fencedPlain[1].trim()); } catch { /* fall through */ }
  }

  // 3. Brace-counted extraction
  const balanced = extractBalancedObject(raw);
  if (balanced) {
    try { return JSON.parse(balanced); } catch { /* fall through */ }
  }

  return null;
}

export function extractJsonArray(raw) {
  if (!raw || typeof raw !== 'string') return [];

  // Try fenced blocks first — they might contain an array or object with array field
  const fencedJson = raw.match(/```json\s*([\s\S]*?)```/);
  if (fencedJson) {
    try {
      const parsed = JSON.parse(fencedJson[1].trim());
      if (Array.isArray(parsed)) return parsed;
      // If it's an object with a findings/results/items/vulns array field, return that
      for (const key of ['findings', 'results', 'items', 'vulns', 'vulnerabilities']) {
        if (Array.isArray(parsed[key])) return parsed[key];
      }
      return [parsed];
    } catch { /* fall through */ }
  }

  // Check for a top-level array
  const arrStart = raw.indexOf('[');
  const objStart = raw.indexOf('{');
  if (arrStart !== -1 && (objStart === -1 || arrStart < objStart)) {
    try {
      const end = raw.lastIndexOf(']');
      if (end > arrStart) {
        return JSON.parse(raw.slice(arrStart, end + 1));
      }
    } catch { /* fall through */ }
  }

  // Fall back to extracting the object and looking for array fields
  const obj = extractJson(raw);
  if (!obj) return [];
  if (Array.isArray(obj)) return obj;
  for (const key of ['findings', 'results', 'items', 'vulns', 'vulnerabilities', 'surface_categories']) {
    if (Array.isArray(obj[key])) return obj[key];
  }
  return [obj];
}
