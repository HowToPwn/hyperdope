import { GoogleGenerativeAI } from '@google/generative-ai';

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

  const result = await genModel.generateContent(user);
  return result.response.text();
}
