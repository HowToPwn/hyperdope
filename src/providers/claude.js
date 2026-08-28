import Anthropic from '@anthropic-ai/sdk';

// FIX PHẦN 12: Scrub API keys from error messages before propagation
const API_KEY_RE = /sk-ant-[A-Za-z0-9_-]{20,}/g;

function scrubApiKey(msg) {
  return typeof msg === 'string' ? msg.replace(API_KEY_RE, 'sk-ant-[REDACTED]') : msg;
}

export async function complete({ system, user, model, api_key, max_tokens = 8192, temperature = 0.2 }) {
  const client = new Anthropic({ apiKey: api_key });

  try {
    const msg = await client.messages.create({
      model,
      max_tokens,
      temperature,
      system,
      messages: [{ role: 'user', content: user }],
    });
    return msg.content.map(b => (b.type === 'text' ? b.text : '')).join('');
  } catch (err) {
    err.message = scrubApiKey(err.message);
    throw err;
  }
}