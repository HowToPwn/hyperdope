import { complete as claudeComplete } from './claude.js';
import { complete as openaiComplete } from './openai.js';
import { complete as geminiComplete } from './gemini.js';
import { complete as ollamaComplete } from './ollama.js';

const OPENAI_COMPAT = new Set(['openai', 'glm', 'kimi', 'qwen', 'gpt']);

export async function callProvider(config, { system, user }) {
  const params = {
    system,
    user,
    model: config.model,
    api_key: config.api_key,
    base_url: config.base_url ?? undefined,
    max_tokens: config.max_tokens ?? 8192,
    temperature: config.temperature ?? 0.2,
  };

  const provider = (config.provider ?? '').toLowerCase();

  if (provider === 'claude' || provider === 'anthropic') {
    return claudeComplete(params);
  }

  if (OPENAI_COMPAT.has(provider)) {
    return openaiComplete(params);
  }

  if (provider === 'gemini' || provider === 'google') {
    return geminiComplete(params);
  }

  if (provider === 'ollama') {
    return ollamaComplete(params);
  }

  // fallback: if base_url is set, assume openai-compatible
  if (config.base_url) {
    return openaiComplete(params);
  }

  throw new Error(`Unknown provider: "${config.provider}". Supported: claude, openai, gemini, ollama, glm, kimi, qwen`);
}
