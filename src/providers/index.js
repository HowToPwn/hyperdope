import { complete as claudeComplete } from './claude.js';
import { complete as openaiComplete } from './openai.js';
import { complete as geminiComplete } from './gemini.js';
import { complete as ollamaComplete } from './ollama.js';
import { withRetry } from '../retry.js';

const OPENAI_COMPAT = new Set(['openai', 'glm', 'kimi', 'qwen', 'gpt']);

export async function callProvider(config, { system, user }) {
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
