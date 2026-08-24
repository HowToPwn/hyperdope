const NO_RETRY_CODES = new Set([400, 401, 403, 404]);

function shouldRetry(err) {
  // Network / fetch errors always retry
  if (!err.status && !err.statusCode) return true;
  const code = err.status ?? err.statusCode;
  if (NO_RETRY_CODES.has(code)) return false;
  return true; // 429, 5xx, anything else
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
