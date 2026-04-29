/**
 * analyze_architecture tool - Architecture security analysis
 */

import { updateArchitecture, requireSession } from '../../session/context';
import { formatArchFinding } from '../../shared/formatter';
import { validateApiKey } from '../../shared/claude-client';
import { detectComponents } from './detector';
import { runRules } from './rules';
import { analyzeLLM } from './llm-analyzer';
import { AnalyzeArchitectureArgs } from './types';

/**
 * analyze_architecture tool implementation
 */
export async function analyzeArchitecture(args: any) {
  const { configFiles, projectPath }: AnalyzeArchitectureArgs = args;

  const session = requireSession();
  const repoPath = projectPath || session.project.path;

  try {
    // Step 1: Detect components
    const detectedComponents = detectComponents(repoPath, configFiles);

    if (detectedComponents.length === 0) {
      return {
        content: [
          {
            type: 'text',
            text:
              '⚠️  No architecture components detected.\n\n' +
              'Supported config files:\n' +
              '  - docker-compose.yml / docker-compose.yaml\n' +
              '  - package.json (for framework detection)\n' +
              '  - .env.example (for environment analysis)\n\n' +
              'Ensure your project has at least one of these configuration files.',
          },
        ],
      };
    }

    // Step 2: Show detected components (confirmation step would go here in interactive mode)
    const componentSummary = detectedComponents
      .map((c) => `  - ${c.name} (${c.type}) - ${c.technology || 'unknown'}`)
      .join('\n');

    // Step 3: Run deterministic rules
    const ruleFindings = runRules(detectedComponents);

    // Step 4: Run LLM analysis (if API key available)
    let llmFindings: typeof ruleFindings = [];
    const hasApiKey = validateApiKey();

    if (hasApiKey) {
      try {
        llmFindings = await analyzeLLM(detectedComponents);
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        console.warn(`LLM analysis failed: ${errorMsg}`);
        // Continue with rule-based findings only
      }
    }

    // Step 5: Merge findings
    const allFindings = [...ruleFindings, ...llmFindings];

    // Sort by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    allFindings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

    // Remove duplicates (same title)
    const uniqueFindings = allFindings.filter(
      (finding, index, self) => index === self.findIndex((f) => f.title === finding.title)
    );

    // Update session
    updateArchitecture({
      components: detectedComponents,
      threats: uniqueFindings,
      analyzedAt: new Date(),
    });

    // Format output
    const output: string[] = [];

    output.push('# Architecture Security Analysis');
    output.push('');
    output.push(`📂 Project: ${session.project.name}`);
    output.push(`🏗️  Components detected: ${detectedComponents.length}`);
    output.push('');

    // Show detected components
    output.push('## Detected Components');
    output.push('');
    output.push(componentSummary);
    output.push('');

    // Analysis methods used
    const methods: string[] = ['Deterministic Rules'];
    if (hasApiKey && llmFindings.length > 0) {
      methods.push('Claude API (STRIDE)');
    }
    output.push(`🔍 Analysis methods: ${methods.join(', ')}`);
    output.push('');

    // Summary
    if (uniqueFindings.length === 0) {
      output.push('✅ No architectural security threats detected!');
      output.push('');
      output.push('The architecture appears sound from a security perspective based on automated analysis.');
      output.push('');
      output.push('**Note:** This is not a complete security audit. Manual review is still recommended.');
    } else {
      const criticalCount = uniqueFindings.filter((f) => f.severity === 'critical').length;
      const highCount = uniqueFindings.filter((f) => f.severity === 'high').length;
      const mediumCount = uniqueFindings.filter((f) => f.severity === 'medium').length;
      const lowCount = uniqueFindings.filter((f) => f.severity === 'low').length;

      const ruleCount = uniqueFindings.filter((f) => f.detectionMethod === 'rule').length;
      const llmCount = uniqueFindings.filter((f) => f.detectionMethod === 'llm').length;

      output.push(`⚠️  Found ${uniqueFindings.length} architectural threat(s):`);
      if (criticalCount > 0) output.push(`  - 🔴 Critical: ${criticalCount}`);
      if (highCount > 0) output.push(`  - 🟠 High: ${highCount}`);
      if (mediumCount > 0) output.push(`  - 🟡 Medium: ${mediumCount}`);
      if (lowCount > 0) output.push(`  - ⚪ Low: ${lowCount}`);
      output.push('');

      output.push(`📊 **Detection:**`);
      output.push(`  - Rule-based: ${ruleCount}`);
      output.push(`  - LLM-based: ${llmCount}`);
      output.push('');

      // STRIDE breakdown
      const strideBreakdown = new Map<string, number>();
      uniqueFindings.forEach((f) => {
        if (f.strideCategory) {
          strideBreakdown.set(
            f.strideCategory,
            (strideBreakdown.get(f.strideCategory) || 0) + 1
          );
        }
      });

      if (strideBreakdown.size > 0) {
        output.push('**STRIDE Breakdown:**');
        strideBreakdown.forEach((count, category) => {
          const displayName = category
            .split('_')
            .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
            .join(' ');
          output.push(`  - ${displayName}: ${count}`);
        });
        output.push('');
      }

      // Show critical/high findings in detail
      const criticalAndHigh = uniqueFindings.filter(
        (f) => f.severity === 'critical' || f.severity === 'high'
      );

      if (criticalAndHigh.length > 0) {
        output.push('## 🔴 Critical & High Severity Threats');
        output.push('');
        criticalAndHigh.forEach((finding) => {
          output.push(formatArchFinding(finding));
        });
      }

      // Summarize medium/low
      const medium = uniqueFindings.filter((f) => f.severity === 'medium');
      const low = uniqueFindings.filter((f) => f.severity === 'low');

      if (medium.length > 0) {
        output.push('## 🟡 Medium Severity Threats');
        output.push('');
        medium.forEach((finding, i) => {
          output.push(
            `${i + 1}. **${finding.title}** - ${finding.affectedComponents.join(', ')}`
          );
        });
        output.push('');
      }

      if (low.length > 0) {
        output.push('## ⚪ Low Severity Threats');
        output.push(`${low.length} low severity threats found.`);
        output.push('');
      }

      // Next steps
      output.push('---');
      output.push('');
      output.push('**💡 Next Steps:**');
      if (criticalCount > 0) {
        output.push('1. 🛑 Address critical architectural issues immediately');
      }
      if (highCount > 0) {
        output.push(
          `${criticalCount > 0 ? '2' : '1'}. ⚠️  Review and fix high severity threats before deployment`
        );
      }
      output.push('- Run `scan_code` to check implementation-level security');
      output.push('- Run `threat_model` to establish security baseline for new features');
      output.push('- Document architectural security decisions');
    }

    if (!hasApiKey) {
      output.push('');
      output.push('---');
      output.push('');
      output.push(
        '💡 **Tip:** Set ANTHROPIC_API_KEY to enable LLM-based STRIDE analysis for deeper insights.'
      );
    }

    return {
      content: [
        {
          type: 'text',
          text: output.join('\n'),
        },
      ],
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [
        {
          type: 'text',
          text: `❌ Error analyzing architecture: ${errorMessage}`,
        },
      ],
      isError: true,
    };
  }
}
