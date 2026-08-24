import OpenAI from 'openai';

export async function complete({ system, user, model, api_key, base_url, max_tokens = 8192, temperature = 0.2 }) {
  const clientOpts = { apiKey: api_key };
  if (base_url) clientOpts.baseURL = base_url;

  const client = new OpenAI(clientOpts);

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
}
