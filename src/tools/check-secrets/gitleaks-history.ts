/**
 * Gitleaks scanner - full git history
 */

import { execSync } from 'child_process';
import { existsSync, mkdirSync, readFileSync, unlinkSync } from 'fs';
import { join } from 'path';
import { GitleaksOutput, GitleaksResult } from './types';

/**
 * Check if gitleaks is installed
 */
export function isGitleaksInstalled(): boolean {
  try {
    execSync('gitleaks version', { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Run gitleaks on working tree
 */
export function scanWorkingTree(projectPath: string): GitleaksResult[] {
  if (!isGitleaksInstalled()) {
    throw new Error(
      'Gitleaks is not installed. Please install it:\n' +
      '  macOS: brew install gitleaks\n' +
      '  Windows: scoop install gitleaks\n' +
      '  Linux: https://github.com/gitleaks/gitleaks#installing'
    );
  }

  const tmpDir = '/tmp';
  if (!existsSync(tmpDir)) {
    mkdirSync(tmpDir, { recursive: true });
  }

  const reportPath = join(tmpDir, `gitleaks-work-${Date.now()}.json`);

  try {
    // Run gitleaks on working tree
    // Note: gitleaks exits with code 1 if secrets are found, which is expected
    try {
      execSync(
        `gitleaks detect --source="${projectPath}" --report-format=json --report-path="${reportPath}" --no-git`,
        { stdio: 'pipe' }
      );
    } catch (error: any) {
      // Exit code 1 means secrets were found - this is OK
      // Exit code 2+ means actual error
      if (error.status && error.status > 1) {
        throw new Error(`Gitleaks error: ${error.message}`);
      }
    }

    // Read results
    if (!existsSync(reportPath)) {
      return []; // No secrets found
    }

    const output = readFileSync(reportPath, 'utf-8');
    const parsed: GitleaksOutput = JSON.parse(output);

    return parsed.results || [];
  } finally {
    // Cleanup
    if (existsSync(reportPath)) {
      unlinkSync(reportPath);
    }
  }
}

/**
 * Run gitleaks on full git history
 */
export function scanFullHistory(projectPath: string): GitleaksResult[] {
  if (!isGitleaksInstalled()) {
    throw new Error(
      'Gitleaks is not installed. Please install it:\n' +
      '  macOS: brew install gitleaks\n' +
      '  Windows: scoop install gitleaks\n' +
      '  Linux: https://github.com/gitleaks/gitleaks#installing'
    );
  }

  const tmpDir = '/tmp';
  if (!existsSync(tmpDir)) {
    mkdirSync(tmpDir, { recursive: true });
  }

  const reportPath = join(tmpDir, `gitleaks-hist-${Date.now()}.json`);

  try {
    // Run gitleaks on full history
    try {
      execSync(
        `gitleaks detect --source="${projectPath}" --log-opts="--all" --report-format=json --report-path="${reportPath}"`,
        { stdio: 'pipe' }
      );
    } catch (error: any) {
      // Exit code 1 means secrets were found - this is OK
      if (error.status && error.status > 1) {
        throw new Error(`Gitleaks error: ${error.message}`);
      }
    }

    // Read results
    if (!existsSync(reportPath)) {
      return []; // No secrets found
    }

    const output = readFileSync(reportPath, 'utf-8');
    const parsed: GitleaksOutput = JSON.parse(output);

    return parsed.results || [];
  } finally {
    // Cleanup
    if (existsSync(reportPath)) {
      unlinkSync(reportPath);
    }
  }
}

/**
 * Run gitleaks on specific branch
 */
export function scanBranch(projectPath: string, branch: string): GitleaksResult[] {
  if (!isGitleaksInstalled()) {
    throw new Error(
      'Gitleaks is not installed. Please install it:\n' +
      '  macOS: brew install gitleaks\n' +
      '  Windows: scoop install gitleaks\n' +
      '  Linux: https://github.com/gitleaks/gitleaks#installing'
    );
  }

  const tmpDir = '/tmp';
  if (!existsSync(tmpDir)) {
    mkdirSync(tmpDir, { recursive: true });
  }

  const reportPath = join(tmpDir, `gitleaks-branch-${Date.now()}.json`);

  try {
    // Run gitleaks on specific branch
    try {
      execSync(
        `gitleaks detect --source="${projectPath}" --log-opts="${branch}" --report-format=json --report-path="${reportPath}"`,
        { stdio: 'pipe' }
      );
    } catch (error: any) {
      // Exit code 1 means secrets were found - this is OK
      if (error.status && error.status > 1) {
        throw new Error(`Gitleaks error: ${error.message}`);
      }
    }

    // Read results
    if (!existsSync(reportPath)) {
      return []; // No secrets found
    }

    const output = readFileSync(reportPath, 'utf-8');
    const parsed: GitleaksOutput = JSON.parse(output);

    return parsed.results || [];
  } finally {
    // Cleanup
    if (existsSync(reportPath)) {
      unlinkSync(reportPath);
    }
  }
}
