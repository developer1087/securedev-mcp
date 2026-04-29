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
    const { execSync } = require('child_process');
    execSync('gitleaks version', { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}
