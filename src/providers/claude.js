import Anthropic from '@anthropic-ai/sdk';

export async function complete({ system, user, model, api_key, max_tokens = 8192, temperature = 0.2 }) {
  const client = new Anthropic({ apiKey: api_key });

  const msg = await client.messages.create({
    model,
    max_tokens,
    temperature,
    system,
    messages: [{ role: 'user', content: user }],
  });

  return msg.content.map(b => (b.type === 'text' ? b.text : '')).join('');
}
