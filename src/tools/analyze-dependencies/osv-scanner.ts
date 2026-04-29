/**
 * OSV-Scanner wrapper for dependency vulnerability scanning
 */

import { execSync } from 'child_process';
import { existsSync } from 'fs';
import { OSVResult, OSVPackage, Ecosystem } from './types';

/**
 * Check if osv-scanner is installed
 */
export function isOSVScannerInstalled(): boolean {
  try {
    execSync('osv-scanner --version', { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Detect lockfile in project
 */
export function detectLockfile(projectPath: string): string | null {
  const lockfiles = [
    'package-lock.json',
    'yarn.lock',
    'pnpm-lock.yaml',
    'requirements.txt',
    'Pipfile.lock',
    'poetry.lock',
    'go.mod',
    'go.sum',
    'Cargo.lock',
    'composer.lock',
    'Gemfile.lock',
  ];

  for (const lockfile of lockfiles) {
    const fullPath = `${projectPath}/${lockfile}`;
    if (existsSync(fullPath)) {
      return lockfile;
    }
  }

  return null;
}

/**
 * Determine ecosystem from lockfile name
 */
export function getEcosystemFromLockfile(lockfile: string): Ecosystem {
  if (lockfile.includes('package')) return 'npm';
  if (lockfile.includes('yarn')) return 'npm';
  if (lockfile.includes('pnpm')) return 'npm';
  if (lockfile.includes('requirements') || lockfile.includes('Pipfile') || lockfile.includes('poetry')) return 'pip';
  if (lockfile.includes('go.')) return 'go';
  if (lockfile.includes('pom.xml') || lockfile.includes('gradle')) return 'maven';
  if (lockfile.includes('packages.config') || lockfile.includes('.csproj')) return 'nuget';

  return 'npm'; // default
}

/**
 * Run osv-scanner on lockfile
 */
export function runOSVScanner(lockfilePath: string, projectPath: string): OSVPackage[] {
  if (!isOSVScannerInstalled()) {
    throw new Error(
      'osv-scanner is not installed. Please install it:\n' +
      '  macOS: brew install osv-scanner\n' +
      '  Linux: curl -sSL https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 -o /usr/local/bin/osv-scanner && chmod +x /usr/local/bin/osv-scanner\n' +
      '  Go: go install github.com/google/osv-scanner/cmd/osv-scanner@latest'
    );
  }

  const fullLockfilePath = lockfilePath.startsWith('/')
    ? lockfilePath
    : `${projectPath}/${lockfilePath}`;

  if (!existsSync(fullLockfilePath)) {
    throw new Error(`Lockfile not found: ${fullLockfilePath}`);
  }

  try {
    let output: string;
    try {
      output = execSync(
        `osv-scanner --format json --lockfile "${fullLockfilePath}"`,
        {
          stdio: 'pipe',
          encoding: 'utf-8',
          maxBuffer: 10 * 1024 * 1024, // 10MB
        }
      );
    } catch (error: any) {
      // osv-scanner exits with code 1 if vulnerabilities are found
      if (error.status === 1 && error.stdout) {
        output = error.stdout;
      } else {
        throw new Error(`osv-scanner error: ${error.stderr || error.message}`);
      }
    }

    // Parse JSON output
    const parsed: OSVResult = JSON.parse(output);
    return parsed.results || [];
  } catch (error) {
    if (error instanceof Error && error.message.includes('not installed')) {
      throw error;
    }
    throw new Error(`osv-scanner failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Extract CVSS score from vulnerability
 */
export function extractCVSS(vuln: any): number | undefined {
  if (!vuln.severity) return undefined;

  for (const sev of vuln.severity) {
    if (sev.type === 'CVSS_V3' && sev.score) {
      // Parse "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" format
      const match = sev.score.match(/CVSS:[\d.]+\/.*?\/.*?\/.*?\/.*?\/.*?\/.*?\/.*?\/.*?$/);
      if (match) {
        // Calculate base score from vector (simplified - should use proper CVSS calculator)
        // For now, estimate based on CIA ratings
        const impact = sev.score.match(/C:([HML])/)?.[1] || 'L';
        const impactScore = impact === 'H' ? 8 : impact === 'M' ? 5 : 2;
        return impactScore;
      }
    }
  }

  // Fallback: try database_specific severity
  if (vuln.database_specific?.severity) {
    const sev = vuln.database_specific.severity.toLowerCase();
    if (sev === 'critical') return 9.0;
    if (sev === 'high') return 7.5;
    if (sev === 'medium' || sev === 'moderate') return 5.0;
    if (sev === 'low') return 3.0;
  }

  return undefined;
}

/**
 * Map OSV severity to our severity levels
 */
export function mapOSVSeverity(vuln: any): 'critical' | 'high' | 'medium' | 'low' {
  const cvss = extractCVSS(vuln);

  if (cvss !== undefined) {
    if (cvss >= 9.0) return 'critical';
    if (cvss >= 7.0) return 'high';
    if (cvss >= 4.0) return 'medium';
    return 'low';
  }

  // Fallback to database_specific severity
  if (vuln.database_specific?.severity) {
    const sev = vuln.database_specific.severity.toLowerCase();
    if (sev === 'critical') return 'critical';
    if (sev === 'high') return 'high';
    if (sev === 'moderate' || sev === 'medium') return 'medium';
    return 'low';
  }

  // Default to medium if unknown
  return 'medium';
}
