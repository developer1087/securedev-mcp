/**
 * Gitleaks scanner for working tree (scan_code specific)
 * Reuses logic from check-secrets tool
 */

import { scanWorkingTree as checkSecretsWorkingTreeScan } from '../check-secrets/gitleaks-history';
import { GitleaksResult } from '../check-secrets/types';

/**
 * Scan working tree for secrets using Gitleaks
 * This is a wrapper around the check-secrets implementation
 */
export function scanWorkingTreeForSecrets(projectPath: string): GitleaksResult[] {
  return checkSecretsWorkingTreeScan(projectPath);
}

/**
 * Check if gitleaks is installed
 */
export function isGitleaksInstalled(): boolean {
  try {
    // Delegate to check-secrets implementation, which also resolves common
    // install locations when PATH doesn't include Homebrew.
    const { isGitleaksInstalled: checkSecretsIsInstalled } = require('../check-secrets/gitleaks-history');
    return Boolean(checkSecretsIsInstalled());
  } catch {
    return false;
  }
}
