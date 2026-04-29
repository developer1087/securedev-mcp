/**
 * Delta report logic - compare threat model baseline to actual findings
 */

import { DeltaReport, ThreatModelFinding, Finding, DepFinding, ArchFinding } from './types';

interface ScanFindings {
  code: Finding[];
  deps: DepFinding[];
  arch?: ArchFinding[];
}

/**
 * Compare threat model baseline to scan findings
 *
 * - Miss: threat identified in threat_model but no mitigation found in scans
 * - OK: threat identified and mitigated (finding exists that addresses it)
 * - New: finding that wasn't anticipated in threat model
 */
export function compareThreatModelToFindings(
  threatModelThreats: ThreatModelFinding[],
  scanFindings: ScanFindings
): DeltaReport {
  const allFindings = [
    ...scanFindings.code,
    ...scanFindings.deps,
    ...(scanFindings.arch || []),
  ];

  const misses: DeltaReport['misses'] = [];
  const ok: DeltaReport['ok'] = [];
  const threatsCovered = new Set<string>();

  // Check each threat from threat model
  for (const threat of threatModelThreats) {
    const mitigatingFinding = findMitigatingFinding(threat, allFindings);

    if (mitigatingFinding) {
      ok.push({
        threat,
        mitigatedBy: mitigatingFinding,
      });
      // Mark finding as covered
      threatsCovered.add(mitigatingFinding.id);
    } else {
      misses.push({
        threat,
        reason: generateMissReason(threat, allFindings),
      });
    }
  }

  // Findings that weren't in threat model = new
  const newFindings = allFindings.filter(
    (finding) => !threatsCovered.has(finding.id)
  );

  return {
    misses,
    ok,
    new: newFindings,
  };
}

/**
 * Find a finding that mitigates/addresses a threat
 */
function findMitigatingFinding(
  threat: ThreatModelFinding,
  findings: Array<Finding | DepFinding | ArchFinding>
): Finding | DepFinding | ArchFinding | null {
  // Strategy 1: Match by CWE
  if (threat.metadata?.cwe) {
    for (const finding of findings) {
      if (finding.metadata?.cwe) {
        const commonCWE = threat.metadata.cwe.find((cwe) =>
          finding.metadata!.cwe!.includes(cwe)
        );
        if (commonCWE) {
          return finding;
        }
      }
    }
  }

  // Strategy 2: Match by STRIDE category (for ArchFindings)
  if (threat.strideCategory) {
    for (const finding of findings) {
      if ('strideCategory' in finding && finding.strideCategory === threat.strideCategory) {
        return finding;
      }
    }
  }

  // Strategy 3: Fuzzy match by title/description keywords
  const threatKeywords = extractKeywords(threat.title + ' ' + threat.description);
  for (const finding of findings) {
    const findingKeywords = extractKeywords(finding.title + ' ' + finding.description);
    const commonKeywords = threatKeywords.filter((kw) =>
      findingKeywords.includes(kw)
    );

    // If >50% keywords match, consider it a mitigation
    if (commonKeywords.length >= Math.ceil(threatKeywords.length * 0.5)) {
      return finding;
    }
  }

  return null;
}

/**
 * Generate a reason why a threat wasn't mitigated
 */
function generateMissReason(
  threat: ThreatModelFinding,
  findings: Array<Finding | DepFinding | ArchFinding>
): string {
  // Check if there are any findings at all
  if (findings.length === 0) {
    return 'No security scans have been run yet';
  }

  // Check if there are findings in the same STRIDE category
  if (threat.strideCategory) {
    const sameCategoryFindings = findings.filter(
      (f) => 'strideCategory' in f && f.strideCategory === threat.strideCategory
    );
    if (sameCategoryFindings.length === 0) {
      return `No findings in ${threat.strideCategory} category - mitigation may not be implemented`;
    }
  }

  // Check if there are findings with overlapping CWEs
  if (threat.metadata?.cwe && threat.metadata.cwe.length > 0) {
    const sameCWEFindings = findings.filter((f) => {
      if (!f.metadata?.cwe) return false;
      return threat.metadata!.cwe!.some((cwe) => f.metadata!.cwe!.includes(cwe));
    });
    if (sameCWEFindings.length === 0) {
      return `No findings for ${threat.metadata.cwe.join(', ')} - specific mitigation not detected`;
    }
  }

  // Generic
  return 'No matching mitigation found in scan results';
}

/**
 * Extract keywords from text (simple implementation)
 */
function extractKeywords(text: string): string[] {
  // Remove common words and extract significant terms
  const commonWords = new Set([
    'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
    'of', 'with', 'by', 'from', 'is', 'are', 'was', 'were', 'be', 'been',
    'this', 'that', 'these', 'those', 'can', 'could', 'may', 'might',
  ]);

  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter((word) => word.length > 3 && !commonWords.has(word))
    .filter((word, index, arr) => arr.indexOf(word) === index); // unique
}

/**
 * Format delta report as markdown summary
 */
export function formatDeltaReport(report: DeltaReport): string {
  const parts: string[] = [];

  parts.push('# Delta Report: Threat Model vs Scan Results');
  parts.push('');

  // Summary
  parts.push(`📊 **Summary:**`);
  parts.push(`- ✅ Mitigated: ${report.ok.length}`);
  parts.push(`- ❌ Missed: ${report.misses.length}`);
  parts.push(`- 🆕 New: ${report.new.length}`);
  parts.push('');

  // Misses (most important)
  if (report.misses.length > 0) {
    parts.push('## ❌ Missed Threats');
    parts.push('Threats identified in threat model but not mitigated:');
    parts.push('');

    report.misses.forEach((miss, i) => {
      parts.push(`### ${i + 1}. ${miss.threat.title}`);
      parts.push(`**Severity:** ${miss.threat.severity.toUpperCase()}`);
      parts.push(`**Reason:** ${miss.reason}`);
      parts.push(`**Description:** ${miss.threat.description}`);
      parts.push('');
    });
  }

  // New findings
  if (report.new.length > 0) {
    parts.push('## 🆕 New Findings');
    parts.push('Findings not anticipated in threat model:');
    parts.push('');

    report.new.forEach((finding, i) => {
      parts.push(`### ${i + 1}. ${finding.title}`);
      parts.push(`**Severity:** ${finding.severity.toUpperCase()}`);
      parts.push('');
    });
  }

  // OK (least important, can be collapsed)
  if (report.ok.length > 0) {
    parts.push('## ✅ Mitigated Threats');
    parts.push(`${report.ok.length} threats successfully mitigated.`);
    parts.push('');
  }

  return parts.join('\n');
}
