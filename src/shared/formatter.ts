/**
 * Formatting utilities for findings and output
 */

import { Finding, DepFinding, ArchFinding, SecretFinding, Severity, InterruptLevel } from './types';
import { getInterruptLevelEmoji } from './interrupt';

/**
 * Format severity as badge
 */
export function formatSeverityBadge(severity: Severity): string {
  const badges = {
    critical: '🔴 CRITICAL',
    high: '🟠 HIGH',
    medium: '🟡 MEDIUM',
    low: '⚪ LOW',
  };
  return badges[severity];
}

/**
 * Format interrupt level as badge
 */
export function formatInterruptBadge(level: InterruptLevel): string {
  const emoji = getInterruptLevelEmoji(level);
  const text = level.replace('_', ' ').toUpperCase();
  return `${emoji} ${text}`;
}

/**
 * Format location as file:line
 */
export function formatLocation(location: { file: string; line?: number; column?: number }): string {
  if (location.line !== undefined) {
    if (location.column !== undefined) {
      return `${location.file}:${location.line}:${location.column}`;
    }
    return `${location.file}:${location.line}`;
  }
  return location.file;
}

/**
 * Mask secret - show only last 4 characters
 */
export function maskSecret(secret: string): string {
  if (secret.length <= 4) {
    return '••••';
  }
  const last4 = secret.slice(-4);
  return `••••${last4}`;
}

/**
 * Format a base finding as markdown
 */
export function formatFinding(finding: Finding): string {
  const parts: string[] = [];

  // Header: severity + interrupt level
  parts.push(`${formatSeverityBadge(finding.severity)} ${formatInterruptBadge(finding.interruptLevel)}`);
  parts.push('');

  // Title
  parts.push(`**${finding.title}**`);
  parts.push('');

  // Description
  parts.push(finding.description);
  parts.push('');

  // Location
  parts.push(`📍 Location: \`${formatLocation(finding.location)}\``);
  parts.push('');

  // Metadata (footer)
  if (finding.metadata) {
    const metadata: string[] = [];

    if (finding.metadata.cwe && finding.metadata.cwe.length > 0) {
      metadata.push(`CWE: ${finding.metadata.cwe.join(', ')}`);
    }

    if (finding.metadata.cvss !== undefined) {
      metadata.push(`CVSS: ${finding.metadata.cvss.toFixed(1)}`);
    }

    if (finding.metadata.owasp && finding.metadata.owasp.length > 0) {
      metadata.push(`OWASP: ${finding.metadata.owasp.join(', ')}`);
    }

    if (metadata.length > 0) {
      parts.push(`ℹ️  ${metadata.join(' | ')}`);
      parts.push('');
    }
  }

  parts.push('---');

  return parts.join('\n');
}

/**
 * Format dependency finding
 */
export function formatDepFinding(finding: DepFinding): string {
  const parts: string[] = [];

  parts.push(`${formatSeverityBadge(finding.severity)} ${formatInterruptBadge(finding.interruptLevel)}`);
  parts.push('');
  parts.push(`**${finding.title}**`);
  parts.push('');
  parts.push(finding.description);
  parts.push('');

  // Package info
  parts.push(`📦 Package: \`${finding.package.name}@${finding.package.version}\``);
  parts.push(`🔗 Ecosystem: ${finding.package.ecosystem}`);
  parts.push(`📊 Depth: ${finding.depthLevel} ${finding.depthLevel === 1 ? '(direct)' : '(transitive)'}`);

  if (finding.depChain && finding.depChain.length > 0) {
    parts.push(`🔍 Chain: ${finding.depChain.join(' → ')}`);
  }

  parts.push('');

  // Vulnerability info
  parts.push(`🆔 ${finding.vulnerability.id}`);
  if (finding.vulnerability.aliases.length > 0) {
    parts.push(`   Aliases: ${finding.vulnerability.aliases.join(', ')}`);
  }

  if (finding.isKEV) {
    parts.push('⚠️  **CISA KEV: Actively exploited in the wild**');
  }

  if (finding.fixAvailable) {
    const breaking = finding.fixAvailable.isBreaking ? ' (⚠️  breaking change)' : '';
    parts.push(`✅ Fix available: upgrade to ${finding.fixAvailable.version}${breaking}`);
  }

  parts.push('');

  // Metadata
  if (finding.metadata) {
    const metadata: string[] = [];
    if (finding.metadata.cvss !== undefined) {
      metadata.push(`CVSS: ${finding.metadata.cvss.toFixed(1)}`);
    }
    if (finding.metadata.cwe && finding.metadata.cwe.length > 0) {
      metadata.push(`CWE: ${finding.metadata.cwe.join(', ')}`);
    }
    if (metadata.length > 0) {
      parts.push(`ℹ️  ${metadata.join(' | ')}`);
      parts.push('');
    }
  }

  parts.push('---');

  return parts.join('\n');
}

/**
 * Format architecture finding
 */
export function formatArchFinding(finding: ArchFinding): string {
  const parts: string[] = [];

  parts.push(`${formatSeverityBadge(finding.severity)} ${formatInterruptBadge(finding.interruptLevel)}`);
  parts.push('');
  parts.push(`**${finding.title}**`);
  parts.push('');
  parts.push(finding.description);
  parts.push('');

  if (finding.strideCategory) {
    parts.push(`🎯 STRIDE: ${finding.strideCategory.replace(/_/g, ' ').toUpperCase()}`);
  }

  parts.push(`🏗️  Affected: ${finding.affectedComponents.join(', ')}`);
  parts.push('');

  // Mitigations
  if (finding.mitigations.length > 0) {
    parts.push('**Recommended Actions:**');
    finding.mitigations.forEach((mitigation, i) => {
      parts.push(`${i + 1}. ${mitigation}`);
    });
    parts.push('');
  }

  // Metadata
  const metadata: string[] = [];
  if (finding.nistControl) {
    metadata.push(`NIST: ${finding.nistControl}`);
  }
  if (finding.metadata?.cwe && finding.metadata.cwe.length > 0) {
    metadata.push(`CWE: ${finding.metadata.cwe.join(', ')}`);
  }
  if (metadata.length > 0) {
    parts.push(`ℹ️  ${metadata.join(' | ')}`);
    parts.push('');
  }

  parts.push('---');

  return parts.join('\n');
}

/**
 * Format secret finding
 */
export function formatSecretFinding(finding: SecretFinding): string {
  const parts: string[] = [];

  parts.push(`${formatSeverityBadge(finding.severity)} ${formatInterruptBadge(finding.interruptLevel)}`);
  parts.push('');
  parts.push(`**${finding.title}**`);
  parts.push('');
  parts.push(finding.description);
  parts.push('');

  parts.push(`🔑 Type: ${finding.secret.type}`);
  parts.push(`🎭 Value: \`${finding.secret.maskedValue}\``);
  parts.push(`📍 Location: \`${formatLocation(finding.location)}\``);
  parts.push(`📊 State: ${finding.state.toUpperCase()}`);

  if (finding.firstSeenCommit) {
    parts.push(`🕐 First seen: ${finding.firstSeenCommit.substring(0, 7)}`);
  }
  if (finding.lastSeenCommit && finding.lastSeenCommit !== finding.firstSeenCommit) {
    parts.push(`🕐 Last seen: ${finding.lastSeenCommit.substring(0, 7)}`);
  }

  parts.push('');

  // Rotation steps
  if (finding.rotationSteps && finding.rotationSteps.length > 0) {
    parts.push('**Rotation Steps:**');
    finding.rotationSteps.forEach((step, i) => {
      parts.push(`${i + 1}. ${step}`);
    });
    parts.push('');
  }

  parts.push('---');

  return parts.join('\n');
}
