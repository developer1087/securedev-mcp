/**
 * get_guidance tool - Security guidance with session context
 */

import { callClaude, validateApiKey } from '../../shared/claude-client';
import { GuidanceResponse } from '../../shared/types';
import { requireSession } from '../../session/context';
import { GetGuidanceArgs, GuidancePromptContext } from './types';

/**
 * Extract session context for prompt
 */
function extractSessionContext(): GuidancePromptContext {
  const session = requireSession();

  const context: GuidancePromptContext = {
    projectName: session.project.name,
    stack: session.project.stack || [],
    threatModelExists: !!session.threatModel,
    secretsFound: !!session.secrets && session.secrets.live.length > 0,
  };

  // Add architecture components if available
  if (session.architecture?.components) {
    context.components = session.architecture.components.map((c) => `${c.name} (${c.type})`);
  }

  // Add findings summary
  if (session.scanFindings || session.architecture || session.secrets) {
    const findings = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };

    // Code findings
    if (session.scanFindings?.code) {
      session.scanFindings.code.forEach((f) => {
        findings[f.severity as keyof typeof findings]++;
      });
    }

    // Dependency findings
    if (session.scanFindings?.deps) {
      session.scanFindings.deps.forEach((f) => {
        findings[f.severity as keyof typeof findings]++;
      });
    }

    // Architecture findings
    if (session.architecture?.threats) {
      session.architecture.threats.forEach((f) => {
        findings[f.severity as keyof typeof findings]++;
      });
    }

    // Secret findings
    if (session.secrets?.live) {
      session.secrets.live.forEach((f) => {
        findings[f.severity as keyof typeof findings]++;
      });
    }

    context.recentFindings = findings;
  }

  return context;
}

/**
 * Build system prompt with context
 */
function buildGuidancePrompt(
  question: string,
  context: GuidancePromptContext,
  mode: 'answer' | 'push'
): string {
  const contextParts: string[] = [];

  contextParts.push(`**Project:** ${context.projectName}`);

  if (context.stack.length > 0) {
    contextParts.push(`**Tech Stack:** ${context.stack.join(', ')}`);
  }

  if (context.components && context.components.length > 0) {
    contextParts.push(`**Components:** ${context.components.join(', ')}`);
  }

  if (context.recentFindings) {
    const { critical, high, medium, low } = context.recentFindings;
    const total = critical + high + medium + low;
    if (total > 0) {
      contextParts.push(
        `**Recent Findings:** ${total} total (${critical} critical, ${high} high, ${medium} medium, ${low} low)`
      );
    }
  }

  if (context.threatModelExists) {
    contextParts.push(`**Threat Model:** Baseline threat model exists in session`);
  }

  if (context.secretsFound) {
    contextParts.push(`**⚠️ Secrets Detected:** Live secrets found in repository`);
  }

  const contextStr = contextParts.join('\n');

  const basePrompt = `You are a security advisor for developers. Your role is to provide actionable, practical security guidance.

**Current Project Context:**
${contextStr}

**User Question:**
${question}

**Guidelines:**
1. **Tone:** Technical but accessible. You're advising a developer, not auditing code.
2. **Actionable:** Provide concrete steps, not just theory.
3. **Context-aware:** Use the project's actual tech stack in examples and recommendations.
4. **References:** Cite CWE, OWASP, NIST, or other standards where relevant.
5. **Code examples:** When helpful, provide code snippets using the project's stack.
6. **Scope awareness:** If the question is outside your scope, explain why and suggest alternatives.

**Out of Scope Topics (escalate these):**
- **Incident Response:** Questions about active breaches, forensics, or compromised systems
- **Architectural Decisions:** Major architecture changes (microservices vs monolith, rewrites)
- **Legal/Compliance:** GDPR, licensing, legal permissions
- **Low Confidence:** If you're unsure or lack context to give good advice

**Response Format (JSON):**
{
  "responseType": "answer" | "escalate",
  "content": "Your main response in markdown format",
  "codeExample": "Optional code snippet (if applicable)",
  "references": ["CWE-89", "OWASP A03:2021"],
  "followUpSuggestions": ["Related question 1", "Related question 2"],
  "escalationReason": "Why this is out of scope (only if escalate)",
  "escalationAlternative": "What you CAN help with instead (only if escalate)"
}

Provide ONLY the JSON response, no additional text.`;

  return basePrompt;
}

/**
 * Detect escalation triggers in question
 */
function shouldEscalate(question: string): { shouldEscalate: boolean; reason?: string; alternative?: string } {
  const lowerQuestion = question.toLowerCase();

  // Incident response
  if (
    lowerQuestion.includes('breach') ||
    lowerQuestion.includes('compromised') ||
    lowerQuestion.includes('hacked') ||
    lowerQuestion.includes('incident') ||
    lowerQuestion.includes('forensic')
  ) {
    return {
      shouldEscalate: true,
      reason: 'This appears to be an incident response question',
      alternative:
        'For active security incidents, contact your security team or incident response provider immediately. ' +
        'I can help with preventive measures, security best practices, and secure development guidance.',
    };
  }

  // Architectural decisions
  if (
    (lowerQuestion.includes('should i') || lowerQuestion.includes('should we')) &&
    (lowerQuestion.includes('rewrite') ||
      lowerQuestion.includes('microservice') ||
      lowerQuestion.includes('monolith') ||
      lowerQuestion.includes('migrate to'))
  ) {
    return {
      shouldEscalate: true,
      reason: 'This is a major architectural decision',
      alternative:
        'I can help with security implications of different architectures, but the decision should involve ' +
        'business stakeholders. I can analyze security trade-offs between options if you provide specifics.',
    };
  }

  // Legal/Compliance
  if (
    lowerQuestion.includes('gdpr') ||
    lowerQuestion.includes('legal') ||
    lowerQuestion.includes('license') ||
    lowerQuestion.includes('compliance') ||
    lowerQuestion.includes('regulation')
  ) {
    return {
      shouldEscalate: true,
      reason: 'This requires legal/compliance expertise',
      alternative:
        'Consult with your legal team or compliance officer for regulatory questions. ' +
        'I can help with technical security controls that support compliance (e.g., encryption, access control).',
    };
  }

  return { shouldEscalate: false };
}

/**
 * Parse Claude response to GuidanceResponse
 */
function parseGuidanceResponse(response: string): GuidanceResponse {
  try {
    // Try to extract JSON from response
    const jsonMatch = response.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      // If no JSON, treat as plain text answer
      return {
        responseType: 'answer',
        content: response,
      };
    }

    const parsed = JSON.parse(jsonMatch[0]);
    return parsed as GuidanceResponse;
  } catch (error) {
    // Fallback to plain text
    return {
      responseType: 'answer',
      content: response,
    };
  }
}

/**
 * Format guidance output
 */
function formatGuidanceOutput(guidance: GuidanceResponse): string {
  const output: string[] = [];

  if (guidance.responseType === 'escalate') {
    output.push('# ⚠️ Question Outside Scope');
    output.push('');
    if (guidance.escalationReason) {
      output.push(`**Reason:** ${guidance.escalationReason}`);
      output.push('');
    }
    if (guidance.escalationAlternative) {
      output.push('**Alternative:**');
      output.push(guidance.escalationAlternative);
      output.push('');
    }
  } else {
    output.push('# Security Guidance');
    output.push('');
  }

  output.push(guidance.content);

  if (guidance.codeExample) {
    output.push('');
    output.push('## Code Example');
    output.push('');
    output.push('```');
    output.push(guidance.codeExample);
    output.push('```');
  }

  if (guidance.references && guidance.references.length > 0) {
    output.push('');
    output.push('## References');
    output.push('');
    guidance.references.forEach((ref) => {
      output.push(`- ${ref}`);
    });
  }

  if (guidance.followUpSuggestions && guidance.followUpSuggestions.length > 0) {
    output.push('');
    output.push('## Related Topics');
    output.push('');
    guidance.followUpSuggestions.forEach((suggestion) => {
      output.push(`- ${suggestion}`);
    });
  }

  return output.join('\n');
}

/**
 * get_guidance tool implementation
 */
export async function getGuidance(args: any) {
  const { question, mode = 'answer', projectPath }: GetGuidanceArgs = args;

  // Validate API key
  if (!validateApiKey()) {
    return {
      content: [
        {
          type: 'text',
          text:
            '❌ ANTHROPIC_API_KEY is not set.\n\n' +
            'The get_guidance tool requires Claude API access.\n' +
            'Please set ANTHROPIC_API_KEY in your environment or MCP configuration.',
        },
      ],
      isError: true,
    };
  }

  try {
    // Check for immediate escalation
    const escalationCheck = shouldEscalate(question);
    if (escalationCheck.shouldEscalate) {
      const guidance: GuidanceResponse = {
        responseType: 'escalate',
        content: escalationCheck.alternative || 'This question is outside my scope.',
        escalationReason: escalationCheck.reason,
        escalationAlternative: escalationCheck.alternative,
      };

      return {
        content: [
          {
            type: 'text',
            text: formatGuidanceOutput(guidance),
          },
        ],
      };
    }

    // Extract session context
    const context = extractSessionContext();

    // Build prompt
    const prompt = buildGuidancePrompt(question, context, mode);

    // Call Claude
    const response = await callClaude(
      [{ role: 'user', content: prompt }],
      {
        temperature: 0.3,
        maxTokens: 3072,
      }
    );

    // Parse response
    const guidance = parseGuidanceResponse(response);

    // Format and return
    const output = formatGuidanceOutput(guidance);

    return {
      content: [
        {
          type: 'text',
          text: output,
        },
      ],
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [
        {
          type: 'text',
          text: `❌ Error getting guidance: ${errorMessage}`,
        },
      ],
      isError: true,
    };
  }
}
