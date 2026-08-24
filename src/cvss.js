// CVSS v3.1 base score calculator — mathematical, not LLM-derived.
// Weights from FIRST.org CVSS v3.1 specification.

const AV_W  = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 };
const AC_W  = { L: 0.77, H: 0.44 };
const PR_W  = {
  U: { N: 0.85, L: 0.62, H: 0.27 },
  C: { N: 0.85, L: 0.68, H: 0.50 },
};
const UI_W  = { N: 0.85, R: 0.62 };
const CIA_W = { N: 0.00, L: 0.22, H: 0.56 };

function roundup(n) {
  return Math.ceil(n * 10) / 10;
}

// Parse a CVSS:3.x/... vector string into a metric map.
// Throws if any required metric is missing or unknown.
export function parseVector(vectorStr) {
  const str = vectorStr.trim();
  if (!str.startsWith('CVSS:3.')) {
    throw new Error(`Not a CVSS v3 vector: ${str}`);
  }
  const parts = str.split('/').slice(1); // drop "CVSS:3.x"
  const map = {};
  for (const part of parts) {
    const [k, v] = part.split(':');
    map[k] = v;
  }

  const required = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
  for (const m of required) {
    if (!(m in map)) throw new Error(`CVSS vector missing metric: ${m} in "${str}"`);
  }

  if (!(map.AV in AV_W)) throw new Error(`Invalid AV: ${map.AV}`);
  if (!(map.AC in AC_W)) throw new Error(`Invalid AC: ${map.AC}`);
  if (!(map.S in PR_W))  throw new Error(`Invalid S: ${map.S}`);
  if (!(map.PR in PR_W[map.S])) throw new Error(`Invalid PR: ${map.PR}`);
  if (!(map.UI in UI_W)) throw new Error(`Invalid UI: ${map.UI}`);
  for (const m of ['C', 'I', 'A']) {
    if (!(map[m] in CIA_W)) throw new Error(`Invalid ${m}: ${map[m]}`);
  }

  return map;
}

export function calculateScore(vectorStr) {
  const m = parseVector(vectorStr);
  const s = m.S; // U or C

  const av = AV_W[m.AV];
  const ac = AC_W[m.AC];
  const pr = PR_W[s][m.PR];
  const ui = UI_W[m.UI];
  const c  = CIA_W[m.C];
  const i  = CIA_W[m.I];
  const a  = CIA_W[m.A];

  const iscBase = 1 - (1 - c) * (1 - i) * (1 - a);

  let isc;
  if (s === 'U') {
    isc = 6.42 * iscBase;
  } else {
    isc = 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
  }

  if (isc <= 0) return 0.0;

  const exploitability = 8.22 * av * ac * pr * ui;

  let score;
  if (s === 'U') {
    score = roundup(Math.min(isc + exploitability, 10));
  } else {
    score = roundup(Math.min(1.08 * (isc + exploitability), 10));
  }

  return score;
}

export function severity(score) {
  if (score === 0.0)  return 'None';
  if (score < 4.0)   return 'Low';
  if (score < 7.0)   return 'Medium';
  if (score < 9.0)   return 'High';
  return 'Critical';
}

// Find the first CVSS:3.x/... vector string in arbitrary text.
export function extractVector(text) {
  const match = text.match(/CVSS:3\.\d\/(?:[A-Z]+:[A-Z]\/)*[A-Z]+:[A-Z]/);
  return match ? match[0] : null;
}
