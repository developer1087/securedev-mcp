/**
 * Claude API client wrapper with retry logic and error handling
 */

import Anthropic from '@anthropic-ai/sdk';

const MODEL = 'claude-sonnet-4-20250514';
const MAX_RETRIES = 3;
const INITIAL_RETRY_DELAY = 1000; // 1 second

export interface ClaudeMessage {
  role: 'user' | 'assistant';
  content: string;
}

export interface ClaudeOptions {
  systemPrompt?: string;
  temperature?: number;
  maxTokens?: number;
}

/**
 * Initialize Claude client
 */
function getClient(): Anthropic {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error(
      'ANTHROPIC_API_KEY environment variable is required for LLM-based tools. ' +
      'Please set it in your .env file or MCP configuration.'
    );
  }

  return new Anthropic({ apiKey });
}

/**
 * Sleep helper for retry delays
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Call Claude API with retry logic
 */
export async function callClaude(
  messages: ClaudeMessage[],
  options: ClaudeOptions = {}
): Promise<string> {
  const client = getClient();
  const {
    systemPrompt,
    temperature = 0.3,
    maxTokens = 4096,
  } = options;

  let lastError: Error | null = null;

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      const response = await client.messages.create({
        model: MODEL,
        max_tokens: maxTokens,
        temperature,
        system: systemPrompt,
        messages: messages.map((msg) => ({
          role: msg.role,
          content: msg.content,
        })),
      });

      // Extract text from response
      const textContent = response.content.find((c) => c.type === 'text');
      if (!textContent || textContent.type !== 'text') {
        throw new Error('No text content in Claude response');
      }

      return textContent.text;
    } catch (error) {
      lastError = error as Error;

      // Check if error is retryable
      if (error instanceof Anthropic.APIError) {
        // Rate limit - always retry with exponential backoff
        if (error.status === 429) {
          const delay = INITIAL_RETRY_DELAY * Math.pow(2, attempt - 1);
          console.warn(
            `Claude API rate limit hit. Retrying in ${delay}ms (attempt ${attempt}/${MAX_RETRIES})...`
          );
          await sleep(delay);
          continue;
        }

        // Server errors (5xx) - retry
        if (error.status && error.status >= 500) {
          const delay = INITIAL_RETRY_DELAY * Math.pow(2, attempt - 1);
          console.warn(
            `Claude API server error (${error.status}). Retrying in ${delay}ms (attempt ${attempt}/${MAX_RETRIES})...`
          );
          await sleep(delay);
          continue;
        }

        // Client errors (4xx except 429) - don't retry
        throw new Error(
          `Claude API error (${error.status}): ${error.message}`
        );
      }

      // Network errors - retry
      if (
        error instanceof Error &&
        (error.message.includes('ECONNRESET') ||
          error.message.includes('ETIMEDOUT') ||
          error.message.includes('ENOTFOUND'))
      ) {
        const delay = INITIAL_RETRY_DELAY * Math.pow(2, attempt - 1);
        console.warn(
          `Network error: ${error.message}. Retrying in ${delay}ms (attempt ${attempt}/${MAX_RETRIES})...`
        );
        await sleep(delay);
        continue;
      }

      // Unknown error - don't retry
      throw error;
    }
  }

  // All retries exhausted
  throw new Error(
    `Claude API call failed after ${MAX_RETRIES} attempts. Last error: ${lastError?.message}`
  );
}

/**
 * Helper to create a simple user message call
 */
export async function askClaude(
  prompt: string,
  options: ClaudeOptions = {}
): Promise<string> {
  return callClaude([{ role: 'user', content: prompt }], options);
}

/**
 * Helper to validate API key without making a request
 */
export function validateApiKey(): boolean {
  return !!process.env.ANTHROPIC_API_KEY;
}
