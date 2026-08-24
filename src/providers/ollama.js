export async function complete({ system, user, model, base_url = 'http://localhost:11434', max_tokens = 8192, temperature = 0.2 }) {
  const endpoint = `${base_url}/v1/chat/completions`;

  const resp = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model,
      max_tokens,
      temperature,
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: user },
      ],
      stream: false,
    }),
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Ollama request failed (${resp.status}): ${text}`);
  }

  const data = await resp.json();
  return data.choices?.[0]?.message?.content ?? '';
}
