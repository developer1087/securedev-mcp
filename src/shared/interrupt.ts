/**
 * InterruptLevel calculation logic
 * Determines how urgently the developer needs to act on a finding
 */

import { Severity, InterruptLevel } from './types';

interface InterruptMetadata {
  cvss?: number;
  hasActivePoc?: boolean;
  isKEV?: boolean; // CISA Known Exploited Vulnerabilities
  isLiveSecret?: boolean;
}

/**
 * Calculate interrupt level based on severity and metadata
 *
 * Rules:
 * - hard_stop: critical severity AND (active PoC OR cvss >= 9.5 OR KEV OR live secret)
 * - action_required: high severity OR (critical without active exploitation)
 * - monitor: medium/low severity
 */
export function calculateInterruptLevel(
  severity: Severity,
  metadata: InterruptMetadata = {}
): InterruptLevel {
  const { cvss, hasActivePoc, isKEV, isLiveSecret } = metadata;

  // Live secrets are always hard_stop
  if (isLiveSecret) {
    return 'hard_stop';
  }

  // Critical with active exploitation
  if (severity === 'critical') {
    if (hasActivePoc || isKEV || (cvss !== undefined && cvss >= 9.5)) {
      return 'hard_stop';
    }
    // Critical but no active exploitation
    return 'action_required';
  }

  // High severity
  if (severity === 'high') {
    return 'action_required';
  }

  // Medium or low
  return 'monitor';
}

/**
 * Get human-readable description of interrupt level
 */
export function getInterruptLevelDescription(
  level: InterruptLevel,
  language: 'he' | 'en' = 'en'
): string {
  const descriptions = {
    hard_stop: {
      he: 'חובה לטפל לפני המשך - פגיעות קריטית עם ניצול פעיל',
      en: 'Must address before proceeding - critical vulnerability with active exploitation',
    },
    action_required: {
      he: 'מומלץ לטפל לפני deploy - פגיעות בעלת חומרה גבוהה',
      en: 'Recommended to address before deploy - high severity vulnerability',
    },
    monitor: {
      he: 'למעקב - פגיעות בעלת חומרה בינונית/נמוכה',
      en: 'Monitor - medium/low severity vulnerability',
    },
  };

  return descriptions[level][language];
}

/**
 * Get emoji indicator for interrupt level
 */
export function getInterruptLevelEmoji(level: InterruptLevel): string {
  const emojis = {
    hard_stop: '🛑',
    action_required: '⚠️',
    monitor: 'ℹ️',
  };

  return emojis[level];
}

/**
 * Determine if finding requires user confirmation before continuing
 */
export function requiresConfirmation(level: InterruptLevel): boolean {
  return level === 'hard_stop';
}
