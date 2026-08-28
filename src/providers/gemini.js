import { GoogleGenerativeAI } from '@google/generative-ai';

// FIX PHẦN 12: Scrub API keys from error messages
const API_KEY_RE = /AIza[0-9A-Za-z_\-]{35}/g;

function scrubApiKey(msg) {
  return typeof msg === 'string' ? msg.replace(API_KEY_RE, 'AIza[REDACTED]') : msg;
}

export async function complete({ system, user, model, api_key, max_tokens = 8192, temperature = 0.2 }) {
  const genAI = new GoogleGenerativeAI(api_key);

  const genModel = genAI.getGenerativeModel({
    model,
    systemInstruction: system,
    generationConfig: {
      maxOutputTokens: max_tokens,
      temperature,
    },
  });

  try {
    const result = await genModel.generateContent(user);
    return result.response.text();
  } catch (err) {
    err.message = scrubApiKey(err.message);
    throw err;
  }
}
