import fetch from 'node-fetch';
import { costTracker } from '../utils/costTracker';

export interface CodeChange {
  filePath: string;
  originalCodeSnippet: string;
  fixedCode: string;
}

type GeminiResponse = {
  candidates?: {
    content?: {
      parts?: { text?: string }[];
    };
  }[];
};

type AIProvider = 'gemini' | 'openai' | 'claude';

export async function callAI(prompt: string, provider: AIProvider, apiKey: string, model: string, operation: string = 'auto-fix', filePath?: string): Promise<string> {
  if (!apiKey) throw new Error('API key is not set in settings.');
  
  // Estimate tokens for cost tracking
  const estimatedInputTokens = Math.ceil(prompt.length / 4); // Rough estimate: 1 token ≈ 4 characters
  
  if (provider === 'gemini') {
    // Gemini API
    try {
      const res = await fetch(
        `https://generativelanguage.googleapis.com/v1/models/${model}:generateContent?key=${apiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contents: [{ parts: [{ text: prompt }] }],
          }),
        }
      );
      if (!res.ok) {
        const errorText = await res.text();
        throw new Error(`Gemini API error ${res.status}: ${errorText}`);
      }
      const json = (await res.json()) as GeminiResponse;
      const response = json.candidates?.[0]?.content?.parts?.[0]?.text ?? 'No response from Gemini API';
      
      // Track cost
      const estimatedOutputTokens = Math.ceil(response.length / 4);
      costTracker.trackApiCall(provider, model, estimatedInputTokens, estimatedOutputTokens, operation, filePath, true);
      
      return response;
    } catch (error) {
      // Track failed call
      costTracker.trackApiCall(provider, model, estimatedInputTokens, 0, operation, filePath, false);
      console.error('Error calling Gemini API:', error);
      throw error;
    }
  } else if (provider === 'openai') {
    // OpenAI API
    try {
      const res = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          model: model,
          messages: [{ role: 'user', content: prompt }],
          temperature: 0.2
        })
      });
      if (!res.ok) {
        const errorText = await res.text();
        throw new Error(`OpenAI API error ${res.status}: ${errorText}`);
      }

      const json = (await res.json()) as {
        choices?: { message?: { content?: string } }[];
      };
      const response = json.choices?.[0]?.message?.content ?? 'No response from OpenAI API';
      
      // Track cost
      const estimatedOutputTokens = Math.ceil(response.length / 4);
      costTracker.trackApiCall(provider, model, estimatedInputTokens, estimatedOutputTokens, operation, filePath, true);
      
      return response;
    } catch (error) {
      // Track failed call
      costTracker.trackApiCall(provider, model, estimatedInputTokens, 0, operation, filePath, false);
      console.error('Error calling OpenAI API:', error);
      throw error;
    }
  } else if (provider === 'claude') {
    // Claude API (Anthropic)
    try {
      const res = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
          model: model,
          max_tokens: 2048,
          messages: [{ role: 'user', content: prompt }]
        })
      });
      if (!res.ok) {
        const errorText = await res.text();
        throw new Error(`Claude API error ${res.status}: ${errorText}`);
      }
      
      const json = (await res.json()) as {
        content?: { text?: string }[];
      };
      const response = json.content?.[0]?.text ?? 'No response from Claude API';
      
      // Track cost
      const estimatedOutputTokens = Math.ceil(response.length / 4);
      costTracker.trackApiCall(provider, model, estimatedInputTokens, estimatedOutputTokens, operation, filePath, true);
      
      return response;
    } catch (error) {
      // Track failed call
      costTracker.trackApiCall(provider, model, estimatedInputTokens, 0, operation, filePath, false);
      console.error('Error calling Claude API:', error);
      throw error;
    }
  } else {
    throw new Error('Unknown AI provider: ' + provider);
  }
}