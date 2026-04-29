/**
 * scan_code tool - SAST-light with Semgrep + Gitleaks
 */

import { v4 as uuidv4 } from 'uuid';
import { Finding } from '../../shared/types';
import { calculateInterruptLevel } from '../../shared/interrupt';
import { formatFinding } from '../../shared/formatter';
import { updateScanFindings, requireSession } from '../../session/context';
import { runSemgrep, mapSemgrepSeverity, isSemgrepInstalled } from './semgrep';
import { scanWorkingTreeForSecrets, isGitleaksInstalled } from './gitleaks-working';
import { ScanCodeArgs, SemgrepResult } from './types';
import { GitleaksResult } from '../check-secrets/types';
import { maskSecret } from '../../shared/formatter';

/**
 * Convert Semgrep result to Finding
 */
function convertSemgrepToFinding(result: SemgrepResult): Finding {
  const severity = mapSemgrepSeverity(result.extra.severity);
  const interruptLevel = calculateInterruptLevel(severity, {
    cvss: result.extra.metadata?.impact === 'HIGH' ? 8.0 : undefined,
  });

  // Extract CWE from metadata
  const cwe = result.extra.metadata?.cwe || [];
  const owasp = result.extra.metadata?.owasp || [];

  return {
    id: uuidv4(),
    title: formatSemgrepTitle(result.check_id),
    description: result.extra.message,
    severity,
    interruptLevel,
    location: {
      file: result.path,
      line: result.start.line,
      column: result.start.col,
    },
    metadata: {
      cwe: cwe.length > 0 ? cwe : undefined,
      owasp: owasp.length > 0 ? owasp : undefined,
      references: [
        `https://semgrep.dev/r/${result.check_id}`,
      ],
    },
    toolSource: 'semgrep',
    foundAt: new Date(),
  };
}

/**
 * Format Semgrep check_id to human-readable title
 */
function formatSemgrepTitle(checkId: string): string {
  // Remove rule prefix (e.g., "javascript.lang.security." → "")
  let title = checkId.replace(/^[^.]+\.[^.]+\./, '');

  // Replace dots and dashes with spaces
  title = title.replace(/[.-]/g, ' ');

  // Capitalize words
  title = title.replace(/\b\w/g, (l) => l.toUpperCase());

  return title;
}

/**
 * Convert Gitleaks result to Finding
 */
function convertGitleaksToFinding(result: GitleaksResult): Finding {
  const severity = 'critical'; // Secrets in working tree are always critical
  const interruptLevel = calculateInterruptLevel(severity, {
    isLiveSecret: true,
  });

  return {
    id: uuidv4(),
    title: `Hardcoded ${result.RuleID.replace(/-/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase())}`,
    description: `Hardcoded credential detected in source code. Secret value: \`${maskSecret(result.Secret)}\``,
    severity,
    interruptLevel,
    location: {
      file: result.File,
      line: result.StartLine,
      column: result.StartColumn,
    },
    metadata: {
      cwe: ['CWE-798'],
      owasp: ['A02:2021'],
      references: [
        'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password',
        'https://cwe.mitre.org/data/definitions/798.html',
      ],
    },
    toolSource: 'gitleaks',
    foundAt: new Date(),
  };
}

/**
 * scan_code tool implementation
 */
export async function scanCode(args: any) {
  const { files = ['.'], projectType, projectPath }: ScanCodeArgs = args;

  const session = requireSession();
  const repoPath = projectPath || session.project.path;

  const findings: Finding[] = [];
  const errors: string[] = [];

  // Check tool availability
  const hasSemgrep = isSemgrepInstalled();
  const hasGitleaks = isGitleaksInstalled();

  if (!hasSemgrep && !hasGitleaks) {
    return {
      content: [
        {
          type: 'text',
          text:
            '❌ Neither Semgrep nor Gitleaks is installed.\n\n' +
            'Please install at least one:\n\n' +
            '**Semgrep (recommended):**\n' +
            '  macOS: brew install semgrep\n' +
            '  Linux/Windows: pip install semgrep\n\n' +
            '**Gitleaks (for secret detection):**\n' +
            '  macOS: brew install gitleaks\n' +
            '  Windows: scoop install gitleaks',
        },
      ],
      isError: true,
    };
  }

  // Run Semgrep
  if (hasSemgrep) {
    try {
      const semgrepResults = runSemgrep(files, repoPath, projectType);
      semgrepResults.forEach((result) => {
        findings.push(convertSemgrepToFinding(result));
      });
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      errors.push(`Semgrep: ${errorMsg}`);
    }
  } else {
    errors.push('Semgrep not installed - skipping code analysis');
  }

  // Run Gitleaks on working tree
  if (hasGitleaks) {
    try {
      const gitleaksResults = scanWorkingTreeForSecrets(repoPath);
      gitleaksResults.forEach((result) => {
        findings.push(convertGitleaksToFinding(result));
      });
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      errors.push(`Gitleaks: ${errorMsg}`);
    }
  } else {
    errors.push('Gitleaks not installed - skipping secret detection');
  }

  // Sort findings by severity (critical → high → medium → low)
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  // Update session
  const existingDeps = session.scanFindings?.deps || [];
  updateScanFindings({
    code: findings,
    deps: existingDeps, // preserve existing dep findings
    scannedAt: new Date(),
  });

  // Format output
  const output: string[] = [];

  output.push('# Code Scan Results (SAST)');
  output.push('');
  output.push(`🔍 Path: ${repoPath}`);
  output.push(`📂 Files: ${files.join(', ')}`);
  if (projectType) {
    output.push(`🏗️  Project type: ${projectType}`);
  }
  output.push('');

  // Tools used
  const toolsUsed: string[] = [];
  if (hasSemgrep) toolsUsed.push('Semgrep');
  if (hasGitleaks) toolsUsed.push('Gitleaks');
  output.push(`🛠️  Tools: ${toolsUsed.join(', ')}`);
  output.push('');

  // Errors (if any)
  if (errors.length > 0) {
    output.push('⚠️  **Warnings:**');
    errors.forEach((err) => output.push(`  - ${err}`));
    output.push('');
  }

  // Summary
  if (findings.length === 0) {
    output.push('✅ No security issues detected!');
    output.push('');
    output.push('This is good news - no vulnerabilities or hardcoded secrets were found in the scanned code.');
  } else {
    const criticalCount = findings.filter((f) => f.severity === 'critical').length;
    const highCount = findings.filter((f) => f.severity === 'high').length;
    const mediumCount = findings.filter((f) => f.severity === 'medium').length;
    const lowCount = findings.filter((f) => f.severity === 'low').length;

    output.push(`⚠️  Found ${findings.length} security issue(s):`);
    if (criticalCount > 0) output.push(`  - 🔴 Critical: ${criticalCount}`);
    if (highCount > 0) output.push(`  - 🟠 High: ${highCount}`);
    if (mediumCount > 0) output.push(`  - 🟡 Medium: ${mediumCount}`);
    if (lowCount > 0) output.push(`  - ⚪ Low: ${lowCount}`);
    output.push('');

    // Group by severity
    const bySeverity = {
      critical: findings.filter((f) => f.severity === 'critical'),
      high: findings.filter((f) => f.severity === 'high'),
      medium: findings.filter((f) => f.severity === 'medium'),
      low: findings.filter((f) => f.severity === 'low'),
    };

    // Show critical findings in detail
    if (bySeverity.critical.length > 0) {
      output.push('## 🔴 Critical Issues');
      output.push('');
      bySeverity.critical.forEach((finding) => {
        output.push(formatFinding(finding));
      });
    }

    // Show high findings in detail
    if (bySeverity.high.length > 0) {
      output.push('## 🟠 High Severity Issues');
      output.push('');
      bySeverity.high.forEach((finding) => {
        output.push(formatFinding(finding));
      });
    }

    // Summarize medium/low
    if (bySeverity.medium.length > 0) {
      output.push('## 🟡 Medium Severity Issues');
      output.push('');
      bySeverity.medium.forEach((finding, i) => {
        output.push(`${i + 1}. **${finding.title}** - \`${finding.location.file}:${finding.location.line}\``);
      });
      output.push('');
    }

    if (bySeverity.low.length > 0) {
      output.push('## ⚪ Low Severity Issues');
      output.push('');
      bySeverity.low.forEach((finding, i) => {
        output.push(`${i + 1}. **${finding.title}** - \`${finding.location.file}:${finding.location.line}\``);
      });
      output.push('');
    }

    // Next steps
    output.push('---');
    output.push('');
    output.push('**💡 Next Steps:**');
    if (criticalCount > 0) {
      output.push('1. 🛑 Address critical issues immediately - these are actively exploitable');
    }
    if (highCount > 0) {
      output.push(`${criticalCount > 0 ? '2' : '1'}. ⚠️  Review and fix high severity issues before deployment`);
    }
    output.push('- Run `analyze_dependencies` to check for vulnerable packages');
    output.push('- Run `check_secrets scope=history` for full git history scan');
  }

  return {
    content: [
      {
        type: 'text',
        text: output.join('\n'),
      },
    ],
  };
}
