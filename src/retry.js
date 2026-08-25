const NO_RETRY_CODES = new Set([400, 401, 403, 404]);

/**
 * Patterns that indicate a connection-level error — i.e. we never reached the
 * remote server at all.  These must NOT be retried because:
 *   1. Retrying a refused connection is purely wasteful (the server is down).
 *   2. More critically, retrying SSRF probe failures amplifies the probe — a
 *      rogue base_url that causes a connection error gets hit 3× instead of 1×,
 *      leaking more timing information about internal topology.
 *
 * We match on the error message because Node's fetch / undici surface network
 * errors without a status code, using only an Error subclass + message text.
 */
const NETWORK_ERROR_RE = /ECONNREFUSED|ENOTFOUND|ECONNRESET|ETIMEDOUT|EHOSTUNREACH|ENETUNREACH|socket hang up|network socket disconnected|getaddrinfo|connect ETIMEDOUT|UND_ERR_CONNECT_TIMEOUT|UND_ERR_SOCKET/i;

function isNetworkError(err) {
  // No HTTP status code at all → originated below the HTTP layer
  if (err.status || err.statusCode) return false;
  // Errno-based or undici error message
  const msg = err.message ?? err.code ?? '';
  return NETWORK_ERROR_RE.test(msg) || err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND';
}

function shouldRetry(err) {
  // Network/connection errors: do NOT retry — avoids SSRF probe amplification
  if (isNetworkError(err)) return false;
  // Hard client errors: no point in retrying
  if (err.status && NO_RETRY_CODES.has(err.status)) return false;
  if (err.statusCode && NO_RETRY_CODES.has(err.statusCode)) return false;
  // 429, 5xx, unknown: retry
  return true;
}

export async function withRetry(fn, { maxAttempts = 3, baseDelayMs = 1000 } = {}) {
  let lastErr;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (!shouldRetry(err) || attempt === maxAttempts) throw err;
      const delay = baseDelayMs * Math.pow(2, attempt - 1);
      await new Promise(r => setTimeout(r, delay));
    }
  }
  throw lastErr;
}
