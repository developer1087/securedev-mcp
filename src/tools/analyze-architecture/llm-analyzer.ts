/**
 * LLM-based architecture analysis using Claude API
 */

import { v4 as uuidv4 } from 'uuid';
import { callClaude, validateApiKey } from '../../shared/claude-client';
import { ArchFinding, StrideCategory, Severity } from '../../shared/types';
import { calculateInterruptLevel } from '../../shared/interrupt';
import { DetectedComponent } from './types';

interface LLMThreat {
  title: string;
  description: string;
  strideCategory: string;
  severity: string;
  affectedComponents: string[];
  cwe?: string[];
  nistControl?: string;
  mitigations: string[];
}

/**
 * Analyze architecture using Claude API
 */
export async function analyzeLLM(components: DetectedComponent[]): Promise<ArchFinding[]> {
  if (!validateApiKey()) {
    throw new Error('ANTHROPIC_API_KEY not configured. Required for architecture analysis.');
  }

  // Build system prompt
  const systemPrompt = `You are a security architect analyzing application architecture for security threats using the STRIDE framework.

STRIDE Categories:
- Spoofing: Authentication/identity threats
- Tampering: Data integrity threats
- Repudiation: Non-repudiation/audit threats
- Information Disclosure: Confidentiality threats
- Denial of Service: Availability threats
- Elevation of Privilege: Authorization threats

Your task:
1. Analyze the provided architecture components
2. Identify STRIDE threats that are CLEARLY PRESENT in the architecture
3. Do NOT speculate - only report threats you can see evidence for
4. For each threat, provide:
   - title: Professional security term (e.g., "SQL Injection via User Input")
   - description: Technical explanation (2-3 sentences)
   - strideCategory: one of the 6 STRIDE categories
   - severity: critical, high, medium, or low
   - affectedComponents: list of component names
   - cwe: relevant CWE IDs (optional)
   - nistControl: NIST 800-53 control (optional)
   - mitigations: actionable steps to fix (3-5 items)

Response format: JSON array of threats
Example:
[
  {
    "title": "Unencrypted Database Connection",
    "description": "The application connects to PostgreSQL without TLS encryption. Database traffic can be intercepted on the network, exposing sensitive data including credentials and user information.",
    "strideCategory": "information_disclosure",
    "severity": "high",
    "affectedComponents": ["application", "postgres"],
    "cwe": ["CWE-319"],
    "nistControl": "SC-8",
    "mitigations": [
      "Enable SSL/TLS in PostgreSQL configuration",
      "Set sslmode=require in connection string",
      "Use certificate-based authentication",
      "Rotate database credentials regularly"
    ]
  }
]

Only include threats with clear evidence in the architecture. Be conservative.`;

  // Build user prompt with architecture details
  const componentDetails = components
    .map((c) => {
      const parts = [`Component: ${c.name}`, `Type: ${c.type}`, `Technology: ${c.technology || 'unknown'}`];

      if (c.ports && c.ports.length > 0) {
        parts.push(`Exposed ports: ${c.ports.join(', ')}`);
      }

      if (c.network) {
        parts.push(`Network: ${c.network}`);
      }

      if (c.environment && Object.keys(c.environment).length > 0) {
        const envKeys = Object.keys(c.environment).slice(0, 10).join(', ');
        parts.push(`Environment variables: ${envKeys}`);
      }

      if (c.routes && c.routes.length > 0) {
        const routePaths = c.routes.map((r) => r.path).slice(0, 5).join(', ');
        parts.push(`Endpoints: ${routePaths}`);
      }

      if (c.dependencies && c.dependencies.length > 0) {
        parts.push(`Dependencies: ${c.dependencies.slice(0, 3).join(', ')}`);
      }

      return parts.join('\n  ');
    })
    .join('\n\n');

  const userPrompt = `Analyze this architecture for STRIDE threats:

${componentDetails}

Remember: Only report threats you can clearly identify from the architecture. Do not speculate about implementation details you cannot see.

Respond with a JSON array of threats.`;

  try {
    // Call Claude API
    const response = await callClaude(
      [{ role: 'user', content: userPrompt }],
      {
        systemPrompt,
        temperature: 0.3,
        maxTokens: 4096,
      }
    );

    // Parse JSON response
    const jsonMatch = response.match(/\[[\s\S]*\]/);
    if (!jsonMatch) {
      console.warn('Claude response did not contain valid JSON array');
      return [];
    }

    const threats: LLMThreat[] = JSON.parse(jsonMatch[0]);

    // Convert to ArchFindings
    const findings: ArchFinding[] = threats.map((threat) => {
      const severity = normalizeSeverity(threat.severity);
      const strideCategory = normalizeStrideCategory(threat.strideCategory);

      return {
        id: uuidv4(),
        title: threat.title,
        description: threat.description,
        severity,
        interruptLevel: calculateInterruptLevel(severity),
        strideCategory,
        affectedComponents: threat.affectedComponents,
        nistControl: threat.nistControl,
        mitigations: threat.mitigations,
        detectionMethod: 'llm',
        metadata: {
          cwe: threat.cwe,
        },
        toolSource: 'manual',
        foundAt: new Date(),
      };
    });

    return findings;
  } catch (error) {
    console.error('LLM analysis failed:', error);
    throw new Error(`Claude API analysis failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Normalize severity string
 */
function normalizeSeverity(severity: string): Severity {
  const normalized = severity.toLowerCase();
  if (normalized === 'critical') return 'critical';
  if (normalized === 'high') return 'high';
  if (normalized === 'medium') return 'medium';
  return 'low';
}

/**
 * Normalize STRIDE category
 */
function normalizeStrideCategory(category: string): StrideCategory {
  const normalized = category.toLowerCase().replace(/[^a-z_]/g, '_');

  if (normalized.includes('spoof')) return 'spoofing';
  if (normalized.includes('tamper')) return 'tampering';
  if (normalized.includes('repudiat')) return 'repudiation';
  if (normalized.includes('information') || normalized.includes('disclosure')) return 'information_disclosure';
  if (normalized.includes('denial') || normalized.includes('service')) return 'denial_of_service';
  if (normalized.includes('elevation') || normalized.includes('privilege')) return 'elevation_of_privilege';

  // Default
  return 'information_disclosure';
}
