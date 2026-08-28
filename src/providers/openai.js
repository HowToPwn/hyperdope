import OpenAI from 'openai';

// FIX PHẦN 12: Scrub API keys from error messages
const API_KEY_RE = /sk-[A-Za-z0-9]{48,}/g;

function scrubApiKey(msg) {
  return typeof msg === 'string' ? msg.replace(API_KEY_RE, 'sk-[REDACTED]') : msg;
}

export async function complete({ system, user, model, api_key, base_url, max_tokens = 8192, temperature = 0.2 }) {
  const clientOpts = { apiKey: api_key };
  if (base_url) clientOpts.baseURL = base_url;

  const client = new OpenAI(clientOpts);

  try {
    const resp = await client.chat.completions.create({
      model,
      max_tokens,
      temperature,
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: user },
      ],
    });
    return resp.choices[0]?.message?.content ?? '';
  } catch (err) {
    err.message = scrubApiKey(err.message);
    throw err;
  }
}
