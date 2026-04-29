/**
 * npm audit wrapper for Node.js dependency scanning
 */

import { execSync } from 'child_process';
import { existsSync } from 'fs';
import { NpmAuditOutput, NpmAuditVulnerability } from './types';

/**
 * Check if npm is installed
 */
export function isNpmInstalled(): boolean {
  try {
    execSync('npm --version', { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Check if project has package-lock.json
 */
export function hasPackageLock(projectPath: string): boolean {
  return existsSync(`${projectPath}/package-lock.json`) ||
         existsSync(`${projectPath}/package.json`);
}

/**
 * Run npm audit
 */
export function runNpmAudit(projectPath: string): Record<string, NpmAuditVulnerability> {
  if (!isNpmInstalled()) {
    throw new Error('npm is not installed');
  }

  if (!hasPackageLock(projectPath)) {
    throw new Error('No package.json or package-lock.json found in project');
  }

  try {
    let output: string;
    try {
      output = execSync('npm audit --json', {
        cwd: projectPath,
        stdio: 'pipe',
        encoding: 'utf-8',
        maxBuffer: 10 * 1024 * 1024,
      });
    } catch (error: any) {
      // npm audit exits with non-zero if vulnerabilities found
      if (error.stdout) {
        output = error.stdout;
      } else {
        throw new Error(`npm audit error: ${error.stderr || error.message}`);
      }
    }

    const parsed: NpmAuditOutput = JSON.parse(output);
    return parsed.vulnerabilities || {};
  } catch (error) {
    throw new Error(`npm audit failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Map npm audit severity to our severity levels
 */
export function mapNpmSeverity(
  npmSeverity: 'info' | 'low' | 'moderate' | 'high' | 'critical'
): 'critical' | 'high' | 'medium' | 'low' {
  switch (npmSeverity) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'moderate':
      return 'medium';
    case 'low':
    case 'info':
      return 'low';
  }
}

/**
 * Extract dependency chain from npm audit vulnerability
 */
export function extractDepChain(vuln: NpmAuditVulnerability): string[] {
  const chain: string[] = [];

  for (const via of vuln.via) {
    if (typeof via !== 'string') {
      chain.push(via.name);
      if (via.dependency && via.dependency !== via.name) {
        chain.push(via.dependency);
      }
    }
  }

  // Add the vulnerable package itself if not in chain
  if (!chain.includes(vuln.name)) {
    chain.push(vuln.name);
  }

  return chain;
}

/**
 * Get CVE/GHSA IDs from npm audit vulnerability
 */
export function extractVulnIds(vuln: NpmAuditVulnerability): string[] {
  const ids: string[] = [];

  for (const via of vuln.via) {
    if (typeof via !== 'string') {
      // Extract CVE or GHSA from URL
      const urlMatch = via.url?.match(/(CVE-\d{4}-\d+|GHSA-[\w-]+)/);
      if (urlMatch) {
        ids.push(urlMatch[1]);
      }
    }
  }

  return ids;
}

/**
 * Get CWE IDs from npm audit vulnerability
 */
export function extractCWEs(vuln: NpmAuditVulnerability): string[] {
  const cwes: string[] = [];

  for (const via of vuln.via) {
    if (typeof via !== 'string' && via.cwe) {
      cwes.push(...via.cwe);
    }
  }

  return cwes;
}

/**
 * Get CVSS score from npm audit vulnerability
 */
export function extractNpmCVSS(vuln: NpmAuditVulnerability): number | undefined {
  for (const via of vuln.via) {
    if (typeof via !== 'string' && via.cvss?.score) {
      return via.cvss.score;
    }
  }

  return undefined;
}
