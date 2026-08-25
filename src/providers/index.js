import { complete as claudeComplete } from './claude.js';
import { complete as openaiComplete } from './openai.js';
import { complete as geminiComplete } from './gemini.js';
import { complete as ollamaComplete } from './ollama.js';
import { withRetry } from '../retry.js';

const OPENAI_COMPAT = new Set(['openai', 'glm', 'kimi', 'qwen', 'gpt']);

// ── base_url SSRF guard ───────────────────────────────────────────────────────

/** Cloud metadata endpoints that must never be targeted. */
const BLOCKED_HOSTS = new Set([
  '169.254.169.254',           // AWS / Azure IMDS
  'metadata.google.internal',  // GCP metadata
  '100.100.100.200',           // Alibaba Cloud metadata
  'fd00:ec2::254',             // AWS IMDS IPv6
]);

/** RFC 1918 private IP ranges — not valid LLM provider endpoints. */
const PRIVATE_RE = [
  /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
  /^172\.(1[6-9]|2\d|30|31)\.\d{1,3}\.\d{1,3}$/,
  /^192\.168\.\d{1,3}\.\d{1,3}$/,
];

/**
 * Validate a base_url before any outbound HTTP request.
 *
 * Rules:
 *   - Must be a syntactically valid URL.
 *   - Must use HTTPS, OR HTTP only when the host is localhost / 127.0.0.1 / ::1
 *     (covers local Ollama deployments).
 *   - Must not target cloud metadata endpoints.
 *   - Must not target RFC 1918 private IP ranges.
 *
 * These checks close the SSRF vector where a caller-controlled base_url causes
 * the server to make credentialed requests to internal or metadata services.
 */
function validateBaseUrl(baseUrl) {
  if (!baseUrl) return;

  let url;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new Error(`base_url is not a valid URL: ${baseUrl}`);
  }

  const isLoopback =
    url.hostname === 'localhost' ||
    url.hostname === '127.0.0.1' ||
    url.hostname === '::1';

  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopback)) {
    throw new Error(
      `base_url must use HTTPS (or HTTP for localhost/127.0.0.1 only). Got: ${baseUrl}`
    );
  }

  // Block 0.0.0.0 — resolves to all-interfaces or loopback depending on OS,
  // neither of which is a valid LLM provider endpoint.
  if (url.hostname === '0.0.0.0') {
    throw new Error(`base_url must not target 0.0.0.0: ${baseUrl}`);
  }

  if (BLOCKED_HOSTS.has(url.hostname)) {
    throw new Error(`base_url targets a blocked metadata host: ${url.hostname}`);
  }

  if (PRIVATE_RE.some(re => re.test(url.hostname))) {
    throw new Error(`base_url must not target private IP ranges: ${url.hostname}`);
  }

  // Block IPv4-mapped IPv6 addresses that bypass the IPv4 checks above.
  // e.g. http://[::ffff:169.254.169.254]/ → url.hostname = '::ffff:169.254.169.254'
  // which does NOT match '169.254.169.254' in BLOCKED_HOSTS.
  const v4mapped = url.hostname.replace(/^\[?::ffff:/i, '').replace(/\]$/, '');
  if (v4mapped !== url.hostname) {
    if (BLOCKED_HOSTS.has(v4mapped) || PRIVATE_RE.some(re => re.test(v4mapped))) {
      throw new Error(
        `base_url must not target IMDS or private ranges via IPv4-mapped IPv6: ${baseUrl}`
      );
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────

export async function callProvider(config, { system, user }) {
  validateBaseUrl(config.base_url);
  const params = {
    system,
    user,
    model:       config.model,
    api_key:     config.api_key,
    base_url:    config.base_url ?? undefined,
    max_tokens:  config.max_tokens ?? 8192,
    temperature: config.temperature ?? 0.2,
  };

  const provider = (config.provider ?? '').toLowerCase();

  let fn;
  if (provider === 'claude' || provider === 'anthropic') {
    fn = () => claudeComplete(params);
  } else if (OPENAI_COMPAT.has(provider)) {
    fn = () => openaiComplete(params);
  } else if (provider === 'gemini' || provider === 'google') {
    fn = () => geminiComplete(params);
  } else if (provider === 'ollama') {
    fn = () => ollamaComplete(params);
  } else if (config.base_url) {
    // fallback: any openai-compatible endpoint
    fn = () => openaiComplete(params);
  } else {
    throw new Error(`Unknown provider: "${config.provider}". Supported: claude, openai, gemini, ollama, glm, kimi, qwen`);
  }

  return withRetry(fn, { maxAttempts: 3, baseDelayMs: 1000 });
}
