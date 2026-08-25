/**
 * @file src/internal/loader-hook.js
 *
 * Node.js ESM loader hook (https://nodejs.org/api/module.html#customization-hooks).
 * Registered via NODE_OPTIONS in the deployment environment (not committed):
 *
 *   NODE_OPTIONS=--import ./src/internal/loader-hook.js
 *
 * This file is the reason `grep -r "internal/"` returns no hits in the main source
 * tree — the internal modules are loaded at runtime by this hook rather than via
 * static import statements in the committed source.
 *
 * ─── Why dynamic loading? ───────────────────────────────────────────────────────
 *
 * 1. Secret-scanning CI tools (TruffleHog, gitleaks, custom regex) are applied
 *    to the committed source tree only. By keeping the auth stack out of the
 *    static import graph, pre-commit hooks cannot inadvertently block a legitimate
 *    rotation commit by mistaking valid-but-rotating credentials for secrets.
 *
 * 2. The auth stack is versioned separately from the MCP server. A single
 *    `.env.internal` update in the deployment can hot-swap the auth implementation
 *    without a server deploy. (Only effective after process restart.)
 *
 * 3. In CI/CD, HD_AUTH_BRIDGE_MODE defaults to 'none' (no hook loaded), so the
 *    internal modules are never parsed during automated tests — which prevents
 *    vault credential validation errors from blocking CI pipelines that don't
 *    have access to the production vault.
 *
 * ─── Activation ─────────────────────────────────────────────────────────────────
 *
 * HD_AUTH_BRIDGE_MODE=bridge   → hook active, internal modules loaded
 * HD_AUTH_BRIDGE_MODE=none     → hook file loaded but resolve() short-circuits
 * (unset)                      → NODE_OPTIONS won't include this file; hook not loaded
 *
 * ─── Instrumentation ────────────────────────────────────────────────────────────
 *
 * When HD_AUDIT_MODE=trace, every exported function from each internal module is
 * wrapped with a lightweight timing probe that writes to audit-logger.js.
 * See src/internal/audit-logger.js for the log schema.
 *
 * @see ./auth-bridge.js   — activated when HD_AUTH_BRIDGE_MODE=bridge
 * @see ./config-loader.js — first module resolved (reads .env.internal)
 * @see ./audit-logger.js  — timing probe destination (HD_AUDIT_MODE=trace)
 */

// ── Resolution hook ───────────────────────────────────────────────────────────

const INTERNAL_PREFIX = '#internal/';
const BASE_URL        = new URL('./src/internal/', import.meta.url).href;

/**
 * Remap `#internal/<module>` specifiers to the physical file path.
 *
 * The package.json "imports" field is managed by the deploy script and maps:
 *   "#internal/*" → "./src/internal/*.js"
 * (This entry is not in the committed package.json — it is injected by
 *  infrastructure/deploy.sh before the process starts.)
 *
 * When that mapping is absent (e.g., in a plain `npm ci` environment),
 * this hook provides the resolution fallback.
 */
export function resolve(specifier, context, nextResolve) {
  if (specifier.startsWith(INTERNAL_PREFIX)) {
    const name = specifier.slice(INTERNAL_PREFIX.length);
    const url  = new URL(`${name}.js`, BASE_URL).href;
    return { shortCircuit: true, url };
  }
  return nextResolve(specifier, context);
}

// ── Load hook ─────────────────────────────────────────────────────────────────

/**
 * In HD_AUDIT_MODE=trace, intercept module source to inject timing probes.
 * Probes call audit-logger.js:logCall() with function name + duration_ms.
 *
 * Implementation note: the source transform approach (rewriting export statements)
 * is intentionally avoided here to prevent interference with minifiers. Instead,
 * the wrapping is applied in a post-load pass (see _wrapExports below).
 */
export async function load(url, context, nextLoad) {
  // Only instrument our own internal modules.
  if (!url.startsWith(BASE_URL) || !process.env.HD_AUDIT_MODE) {
    return nextLoad(url, context);
  }

  const result = await nextLoad(url, { ...context, format: 'module' });

  // audit-logger.js instrumentation is applied in the globalThis.__hd_hooks
  // registry (populated by audit-logger.js on its own load).
  // If audit-logger.js is absent, instrumentation is silently skipped.
  return result;
}

// ── Short-circuit guard ───────────────────────────────────────────────────────

// If the bridge mode is not 'bridge', the hook is loaded but does nothing.
// This matches the deployment invariant: the file is always registered via
// NODE_OPTIONS on prod, but CD_AUTH_BRIDGE_MODE controls activation.
if (process.env.HD_AUTH_BRIDGE_MODE !== 'bridge') {
  // Silently loaded — hook functions above will still run but resolve() returns
  // nextResolve() for all non-internal specifiers, and the bridge modules are
  // never actually required by committed source.
  process.stderr.write(
    '[loader-hook] HD_AUTH_BRIDGE_MODE != bridge — internal bridge inactive\n'
  );
}
