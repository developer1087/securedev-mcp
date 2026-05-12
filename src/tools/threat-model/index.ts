/**
 * threat_model tool - Proactive STRIDE threat modeling
 */

import { v4 as uuidv4 } from 'uuid';
import { callClaude, validateApiKey } from '../../shared/claude-client';
import { Feature, ThreatModelFinding, StrideCategory, Severity } from '../../shared/types';
import { requireSession, updateThreatModel, getSession } from '../../session/context';
import { ThreatModelArgs, ClarifyingQuestions, StrideAnalysisResponse } from './types';
import { ProgressReporter } from '../../shared/progress';

/**
 * Standard clarifying questions
 */
function getClarifyingQuestions(): ClarifyingQuestions {
  return {
    questions: [
      {
        id: 'accessControl',
        question: 'Who can access this feature?',
        options: ['public', 'authenticated', 'admin'],
      },
      {
        id: 'dataVisibility',
        question: 'Is the data visible to others?',
        options: ['public', 'friends', 'private'],
      },
      {
        id: 'storage',
        question: 'How is the data stored?',
        options: ['db', 'file', 'cloud', 'memory'],
      },
      {
        id: 'processingType',
        question: 'What type of data processing occurs? (e.g., validation, transformation, encryption)',
        options: ['validation', 'transformation', 'encryption', 'none', 'other'],
      },
    ],
  };
}

/**
 * Build STRIDE system prompt with context
 */
function buildStridePrompt(
  featureDescription: string,
  clarifications: any,
  session: any
): string {
  const contextParts: string[] = [];

  // Add project context
  contextParts.push(`Project: ${session.project.name}`);
  if (session.project.stack && session.project.stack.length > 0) {
    contextParts.push(`Tech Stack: ${session.project.stack.join(', ')}`);
  }

  // Add architecture context if available
  if (session.architecture?.components && session.architecture.components.length > 0) {
    const componentsList = session.architecture.components
      .map((c: any) => `- ${c.name} (${c.type})${c.technology ? ': ' + c.technology : ''}`)
      .join('\n');
    contextParts.push(`Existing Components:\n${componentsList}`);
  }

  const context = contextParts.join('\n');

  return `You are a security architect performing threat modeling using the STRIDE framework.

**Feature Description:**
${featureDescription}

**Feature Context:**
- Access Control: ${clarifications.accessControl || 'unknown'}
- Data Visibility: ${clarifications.dataVisibility || 'unknown'}
- Storage: ${clarifications.storage || 'unknown'}
- Processing: ${clarifications.processingType || 'unknown'}

**Project Context:**
${context}

**Task:**
Perform a STRIDE threat analysis for this feature. For each applicable STRIDE category, identify specific threats.

**IMPORTANT:**
- Only include STRIDE categories that are relevant to this feature
- For categories that are NOT applicable, briefly explain why (1 sentence)
- Be specific - reference actual implementation details from the feature description and project context where possible
- Focus on realistic, actionable threats

**STRIDE Categories:**
- Spoofing: Identity verification threats
- Tampering: Data integrity threats
- Repudiation: Logging/audit threats
- Information Disclosure: Data confidentiality threats
- Denial of Service: Availability threats
- Elevation of Privilege: Authorization threats

**Response Format (JSON):**
{
  "threats": [
    {
      "strideCategory": "spoofing" | "tampering" | "repudiation" | "information_disclosure" | "denial_of_service" | "elevation_of_privilege",
      "title": "Professional, technical title (e.g., 'Session Token Fixation')",
      "description": "Detailed technical explanation of the threat",
      "severity": "critical" | "high" | "medium" | "low",
      "likelihood": "low" | "medium" | "high",
      "impact": "low" | "medium" | "high",
      "mitigations": ["Actionable step 1", "Actionable step 2"],
      "cwe": ["CWE-ID"],
      "cvssVector": "CVSS:3.1/...",
      "references": ["https://..."]
    }
  ],
  "notApplicable": [
    {
      "strideCategory": "repudiation",
      "reason": "Feature does not involve user actions that need auditing"
    }
  ]
}

Provide ONLY the JSON response, no additional text.`;
}

/**
 * Parse Claude response to structured threats
 */
function parseStrideResponse(
  response: string,
  featureId: string
): ThreatModelFinding[] {
  try {
    // Try to extract JSON from response (in case Claude adds extra text)
    const jsonMatch = response.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      throw new Error('No JSON found in response');
    }

    const parsed: StrideAnalysisResponse = JSON.parse(jsonMatch[0]);

    return parsed.threats.map((threat) => ({
      id: uuidv4(),
      featureId,
      title: threat.title,
      description: threat.description,
      strideCategory: threat.strideCategory as StrideCategory,
      severity: threat.severity as Severity,
      mitigations: threat.mitigations,
      likelihood: threat.likelihood as 'low' | 'medium' | 'high',
      impact: threat.impact as 'low' | 'medium' | 'high',
      metadata: {
        cwe: threat.cwe,
        cvssVector: threat.cvssVector,
        references: threat.references,
      },
    }));
  } catch (error) {
    throw new Error(`Failed to parse STRIDE response: ${error}`);
  }
}

/**
 * Format threat model output
 */
function formatThreatModelOutput(feature: Feature, isFirstRun: boolean): string {
  const output: string[] = [];

  output.push('# Threat Model Results');
  output.push('');
  output.push(`## Feature: ${feature.name}`);
  output.push('');
  output.push(`**Description:** ${feature.description}`);
  output.push('');

  output.push('**Context:**');
  output.push(`- Access Control: ${feature.context.accessControl}`);
  output.push(`- Data Visibility: ${feature.context.dataVisibility}`);
  output.push(`- Storage: ${feature.context.storage}`);
  if (feature.context.processingType) {
    output.push(`- Processing: ${feature.context.processingType}`);
  }
  output.push('');

  if (feature.threats.length === 0) {
    output.push('✅ No significant threats identified for this feature.');
    output.push('');
    output.push('This is unusual - you may want to review the feature description and context.');
    return output.join('\n');
  }

  // Group threats by STRIDE category
  const strideGroups = new Map<string, ThreatModelFinding[]>();
  feature.threats.forEach((threat) => {
    const category = threat.strideCategory;
    if (!strideGroups.has(category)) {
      strideGroups.set(category, []);
    }
    strideGroups.get(category)!.push(threat);
  });

  output.push(`## STRIDE Analysis`);
  output.push('');
  output.push(`Found **${feature.threats.length} threat(s)** across **${strideGroups.size} STRIDE categories**:`);
  output.push('');

  // Display threats by category
  const categoryNames: Record<string, string> = {
    spoofing: 'Spoofing (Identity)',
    tampering: 'Tampering (Data Integrity)',
    repudiation: 'Repudiation (Audit/Logging)',
    information_disclosure: 'Information Disclosure (Confidentiality)',
    denial_of_service: 'Denial of Service (Availability)',
    elevation_of_privilege: 'Elevation of Privilege (Authorization)',
  };

  for (const [category, threats] of strideGroups.entries()) {
    const categoryName = categoryNames[category] || category;
    output.push(`### ${categoryName}`);
    output.push('');

    threats.forEach((threat, i) => {
      const severityIcon = threat.severity === 'critical' ? '🔴' :
                          threat.severity === 'high' ? '🟠' :
                          threat.severity === 'medium' ? '🟡' : '🔵';

      output.push(`#### ${i + 1}. ${threat.title} ${severityIcon}`);
      output.push('');
      output.push(`**Severity:** ${threat.severity.toUpperCase()}`);
      output.push(`**Likelihood:** ${threat.likelihood} | **Impact:** ${threat.impact}`);
      output.push('');
      output.push(`**Description:**`);
      output.push(threat.description);
      output.push('');

      if (threat.mitigations && threat.mitigations.length > 0) {
        output.push('**Recommended Mitigations:**');
        threat.mitigations.forEach((mitigation, j) => {
          output.push(`${j + 1}. ${mitigation}`);
        });
        output.push('');
      }

      if (threat.metadata?.cwe && threat.metadata.cwe.length > 0) {
        output.push(`**CWE:** ${threat.metadata.cwe.join(', ')}`);
      }
      if (threat.metadata?.cvssVector) {
        output.push(`**CVSS:** ${threat.metadata.cvssVector}`);
      }
      output.push('');
    });
  }

  output.push('---');
  output.push('');

  if (isFirstRun) {
    output.push('✅ **Baseline threat model saved to session**');
    output.push('');
    output.push('This baseline will be compared against actual findings from scan_code and analyze_dependencies.');
    output.push('Run those tools to see if the identified threats are properly mitigated in your code.');
  } else {
    output.push('ℹ️  Threat model updated in session');
  }

  return output.join('\n');
}

/**
 * threat_model tool implementation
 */
export async function threatModel(args: any, progress: ProgressReporter) {
  const { featureDescription, clarifications, projectPath }: ThreatModelArgs = args;

  await progress.step(1, 3, 'Initializing threat model...');

  // Validate API key
  if (!validateApiKey()) {
    return {
      content: [
        {
          type: 'text',
          text:
            '❌ ANTHROPIC_API_KEY is not set.\n\n' +
            'The threat_model tool requires Claude API access.\n' +
            'Please set ANTHROPIC_API_KEY in your environment or MCP configuration.',
        },
      ],
      isError: true,
    };
  }

  const session = requireSession();

  // If no clarifications provided, return questions
  if (!clarifications) {
    const questions = getClarifyingQuestions();

    const output: string[] = [];
    output.push('# Threat Modeling - Clarifying Questions');
    output.push('');
    output.push(`**Feature:** ${featureDescription}`);
    output.push('');
    output.push('To perform accurate threat modeling, please provide answers to these questions:');
    output.push('');

    questions.questions.forEach((q, i) => {
      output.push(`**${i + 1}. ${q.question}**`);
      output.push(`Options: ${q.options.join(', ')}`);
      output.push('');
    });

    output.push('---');
    output.push('');
    output.push('Once you have the answers, re-run the tool with:');
    output.push('```json');
    output.push('{');
    output.push(`  "featureDescription": "${featureDescription}",`);
    output.push('  "clarifications": {');
    output.push('    "accessControl": "authenticated",  // your answer');
    output.push('    "dataVisibility": "private",       // your answer');
    output.push('    "storage": "db",                   // your answer');
    output.push('    "processingType": "validation"     // your answer');
    output.push('  }');
    output.push('}');
    output.push('```');

    return {
      content: [
        {
          type: 'text',
          text: output.join('\n'),
        },
      ],
    };
  }

  // Perform STRIDE analysis with Claude
  try {
    await progress.step(2, 3, 'Analyzing feature with STRIDE framework via Claude API...');

    const prompt = buildStridePrompt(featureDescription, clarifications, session);

    const response = await callClaude(
      [{ role: 'user', content: prompt }],
      {
        temperature: 0.3,
        maxTokens: 4096,
      }
    );

    await progress.step(3, 3, 'Processing and formatting threat model results...');

    // Create feature object
    const featureId = uuidv4();
    const feature: Feature = {
      id: featureId,
      name: featureDescription.split('\n')[0].substring(0, 100), // First line as name
      description: featureDescription,
      context: {
        accessControl: clarifications.accessControl || 'authenticated',
        dataVisibility: clarifications.dataVisibility || 'private',
        storage: clarifications.storage || 'db',
        hasProcessing: !!clarifications.processingType && clarifications.processingType !== 'none',
        processingType: clarifications.processingType,
      },
      threats: [],
    };

    // Parse threats
    const threats = parseStrideResponse(response, featureId);
    feature.threats = threats;

    // Check if this is the first threat model
    const isFirstRun = !session.threatModel;

    // Update session
    const existingFeatures = session.threatModel?.features || [];
    const allThreats = [
      ...(session.threatModel?.threats || []),
      ...threats,
    ];

    updateThreatModel({
      features: [...existingFeatures, feature],
      threats: allThreats,
      savedAt: new Date(),
    });

    // Format and return output
    const output = formatThreatModelOutput(feature, isFirstRun);

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
          text: `❌ Error performing threat modeling: ${errorMessage}`,
        },
      ],
      isError: true,
    };
  }
}
