/**
 * Security score calculation
 *
 * Formula:
 * score = 100
 *   - (critical_findings * 15)
 *   - (high_findings * 7)
 *   - (medium_findings * 3)
 *   - (low_findings * 1)
 *   - (delta_misses * 10)
 *   - (live_secrets * 20)
 *   + (tools_run * 2)
 * min(score, 0)
 */

import { SessionContext, ScoreBreakdown, Severity } from '../shared/types';
import { compareThreatModelToFindings } from '../shared/delta';

/**
 * Calculate overall security score for the session
 */
export function calculateScore(session: SessionContext): ScoreBreakdown {
  let score = 100;

  // Count findings by severity
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  // Scan findings (code + deps)
  if (session.scanFindings) {
    for (const finding of session.scanFindings.code) {
      counts[finding.severity]++;
    }
    for (const finding of session.scanFindings.deps) {
      counts[finding.severity]++;
    }
  }

  // Architecture findings
  if (session.architecture) {
    for (const finding of session.architecture.threats) {
      counts[finding.severity]++;
    }
  }

  // Secrets (all secrets are critical)
  let liveSecretsCount = 0;
  if (session.secrets) {
    liveSecretsCount = session.secrets.live.filter(
      (s) => s.state === 'live'
    ).length;
  }

  // Delta misses
  let deltaMissesCount = 0;
  if (session.threatModel && session.scanFindings) {
    const delta = compareThreatModelToFindings(
      session.threatModel.threats,
      {
        code: session.scanFindings.code,
        deps: session.scanFindings.deps,
        arch: session.architecture?.threats,
      }
    );
    deltaMissesCount = delta.misses.length;
  }

  // Tools run (bonus points)
  let toolsRunCount = 0;
  if (session.scanFindings) toolsRunCount++;
  if (session.architecture) toolsRunCount++;
  if (session.threatModel) toolsRunCount++;
  if (session.secrets) toolsRunCount++;
  if (session.sbom) toolsRunCount++;

  // Calculate deductions
  const criticalImpact = counts.critical * 15;
  const highImpact = counts.high * 7;
  const mediumImpact = counts.medium * 3;
  const lowImpact = counts.low * 1;
  const deltaMissesImpact = deltaMissesCount * 10;
  const liveSecretsImpact = liveSecretsCount * 20;
  const toolsBonus = toolsRunCount * 2;

  // Apply formula
  score -= criticalImpact;
  score -= highImpact;
  score -= mediumImpact;
  score -= lowImpact;
  score -= deltaMissesImpact;
  score -= liveSecretsImpact;
  score += toolsBonus;

  // Min 0
  score = Math.max(score, 0);

  return {
    total: Math.round(score),
    breakdown: {
      criticalFindings: {
        count: counts.critical,
        impact: -criticalImpact,
      },
      highFindings: {
        count: counts.high,
        impact: -highImpact,
      },
      mediumFindings: {
        count: counts.medium,
        impact: -mediumImpact,
      },
      lowFindings: {
        count: counts.low,
        impact: -lowImpact,
      },
      deltaMisses: {
        count: deltaMissesCount,
        impact: -deltaMissesImpact,
      },
      liveSecrets: {
        count: liveSecretsCount,
        impact: -liveSecretsImpact,
      },
      toolsRun: {
        count: toolsRunCount,
        bonus: toolsBonus,
      },
    },
  };
}

/**
 * Get score color based on value
 */
export function getScoreColor(score: number): 'green' | 'amber' | 'red' {
  if (score > 80) return 'green';
  if (score >= 60) return 'amber';
  return 'red';
}

/**
 * Get score grade (A-F)
 */
export function getScoreGrade(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

/**
 * Format score breakdown as markdown
 */
export function formatScoreBreakdown(breakdown: ScoreBreakdown): string {
  const parts: string[] = [];

  const color = getScoreColor(breakdown.total);
  const grade = getScoreGrade(breakdown.total);
  const colorEmoji = color === 'green' ? '🟢' : color === 'amber' ? '🟡' : '🔴';

  parts.push(`# Security Score: ${breakdown.total}/100 ${colorEmoji} (${grade})`);
  parts.push('');

  parts.push('## Breakdown');
  parts.push('');

  // Deductions
  parts.push('### Deductions');
  if (breakdown.breakdown.criticalFindings.count > 0) {
    parts.push(
      `- 🔴 Critical findings: ${breakdown.breakdown.criticalFindings.count} × 15 = ${breakdown.breakdown.criticalFindings.impact}`
    );
  }
  if (breakdown.breakdown.highFindings.count > 0) {
    parts.push(
      `- 🟠 High findings: ${breakdown.breakdown.highFindings.count} × 7 = ${breakdown.breakdown.highFindings.impact}`
    );
  }
  if (breakdown.breakdown.mediumFindings.count > 0) {
    parts.push(
      `- 🟡 Medium findings: ${breakdown.breakdown.mediumFindings.count} × 3 = ${breakdown.breakdown.mediumFindings.impact}`
    );
  }
  if (breakdown.breakdown.lowFindings.count > 0) {
    parts.push(
      `- ⚪ Low findings: ${breakdown.breakdown.lowFindings.count} × 1 = ${breakdown.breakdown.lowFindings.impact}`
    );
  }
  if (breakdown.breakdown.deltaMisses.count > 0) {
    parts.push(
      `- ❌ Delta misses: ${breakdown.breakdown.deltaMisses.count} × 10 = ${breakdown.breakdown.deltaMisses.impact}`
    );
  }
  if (breakdown.breakdown.liveSecrets.count > 0) {
    parts.push(
      `- 🔑 Live secrets: ${breakdown.breakdown.liveSecrets.count} × 20 = ${breakdown.breakdown.liveSecrets.impact}`
    );
  }

  parts.push('');

  // Bonuses
  parts.push('### Bonuses');
  if (breakdown.breakdown.toolsRun.count > 0) {
    parts.push(
      `- ✅ Tools run: ${breakdown.breakdown.toolsRun.count} × 2 = +${breakdown.breakdown.toolsRun.bonus}`
    );
  } else {
    parts.push('- No tools run yet');
  }

  parts.push('');

  // Interpretation
  parts.push('## Interpretation');
  if (breakdown.total >= 80) {
    parts.push('✅ **Good security posture.** Continue monitoring and address any remaining findings.');
  } else if (breakdown.total >= 60) {
    parts.push('⚠️  **Moderate security posture.** Address high/critical findings before deployment.');
  } else {
    parts.push('🛑 **Poor security posture.** Immediate action required on critical/high findings.');
  }

  return parts.join('\n');
}
