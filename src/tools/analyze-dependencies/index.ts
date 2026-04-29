/**
 * analyze_dependencies tool - SCA with osv-scanner + npm audit
 */

import { v4 as uuidv4 } from 'uuid';
import { readFileSync, existsSync } from 'fs';
import { DepFinding } from '../../shared/types';
import { calculateInterruptLevel } from '../../shared/interrupt';
import { formatDepFinding } from '../../shared/formatter';
import { updateScanFindings, requireSession } from '../../session/context';
import {
  runOSVScanner,
  detectLockfile,
  getEcosystemFromLockfile,
  isOSVScannerInstalled,
  mapOSVSeverity,
  extractCVSS,
} from './osv-scanner';
import {
  runNpmAudit,
  isNpmInstalled,
  hasPackageLock,
  mapNpmSeverity,
  extractDepChain,
  extractVulnIds,
  extractCWEs,
  extractNpmCVSS,
} from './npm-audit';
import { AnalyzeDependenciesArgs, OSVPackage, NpmAuditVulnerability, Ecosystem } from './types';

/**
 * Determine dependency depth by checking if package is in package.json dependencies
 */
function getDependencyDepth(packageName: string, projectPath: string): number {
  try {
    const packageJsonPath = `${projectPath}/package.json`;
    if (!existsSync(packageJsonPath)) {
      return 2; // assume transitive if no package.json
    }

    const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));
    const allDeps = {
      ...packageJson.dependencies,
      ...packageJson.devDependencies,
      ...packageJson.peerDependencies,
    };

    return allDeps[packageName] ? 1 : 2;
  } catch {
    return 2; // default to transitive on error
  }
}

/**
 * Check if vulnerability is in CISA KEV list (simplified check)
 * In production, this should query the actual KEV API
 */
function isKEV(vulnId: string): boolean {
  // Simplified: just check if it's a CVE with high score
  // Real implementation should query: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  return vulnId.startsWith('CVE-') && false; // Always false for now - Phase 2: implement real KEV check
}

/**
 * Convert OSV package to DepFindings
 */
function convertOSVToDepFindings(
  osvPackage: OSVPackage,
  projectPath: string,
  ecosystem: Ecosystem
): DepFinding[] {
  const findings: DepFinding[] = [];

  for (const vuln of osvPackage.vulnerabilities) {
    const severity = mapOSVSeverity(vuln);
    const cvss = extractCVSS(vuln);
    const isKEVFlag = isKEV(vuln.id);

    const interruptLevel = calculateInterruptLevel(severity, {
      cvss,
      isKEV: isKEVFlag,
    });

    const depth = getDependencyDepth(osvPackage.package.name, projectPath);

    // Extract CWE IDs
    const cwes = vuln.database_specific?.cwe_ids || [];

    // Check for fix
    let fixAvailable: DepFinding['fixAvailable'] = undefined;
    if (vuln.affected && vuln.affected.length > 0) {
      for (const affected of vuln.affected) {
        if (affected.ranges) {
          for (const range of affected.ranges) {
            for (const event of range.events) {
              if (event.fixed) {
                fixAvailable = {
                  version: event.fixed,
                  isBreaking: false, // Can't determine from OSV data
                };
                break;
              }
            }
            if (fixAvailable) break;
          }
        }
        if (fixAvailable) break;
      }
    }

    findings.push({
      id: uuidv4(),
      title: vuln.summary || `Vulnerability in ${osvPackage.package.name}`,
      description: vuln.details || vuln.summary || 'No description available',
      severity,
      interruptLevel,
      package: {
        name: osvPackage.package.name,
        version: osvPackage.package.version,
        ecosystem,
      },
      vulnerability: {
        id: vuln.id,
        aliases: vuln.aliases || [],
        publishedAt: vuln.published ? new Date(vuln.published) : undefined,
        lastModified: vuln.modified ? new Date(vuln.modified) : undefined,
      },
      depthLevel: depth,
      isKEV: isKEVFlag,
      fixAvailable,
      metadata: {
        cvss,
        cwe: cwes.length > 0 ? cwes : undefined,
        references: vuln.references?.map((r) => r.url) || [],
      },
      toolSource: 'osv-scanner',
      foundAt: new Date(),
    });
  }

  return findings;
}

/**
 * Convert npm audit vulnerability to DepFinding
 */
function convertNpmAuditToDepFinding(
  packageName: string,
  vuln: NpmAuditVulnerability,
  projectPath: string
): DepFinding[] {
  const findings: DepFinding[] = [];
  const vulnIds = extractVulnIds(vuln);
  const cwes = extractCWEs(vuln);
  const depChain = extractDepChain(vuln);
  const cvss = extractNpmCVSS(vuln);

  // Get title from via
  let title = `Vulnerability in ${packageName}`;
  for (const via of vuln.via) {
    if (typeof via !== 'string' && via.title) {
      title = via.title;
      break;
    }
  }

  const severity = mapNpmSeverity(vuln.severity);
  const isKEVFlag = vulnIds.some((id) => isKEV(id));

  const interruptLevel = calculateInterruptLevel(severity, {
    cvss,
    isKEV: isKEVFlag,
  });

  const depth = getDependencyDepth(packageName, projectPath);

  // Fix available
  let fixAvailable: DepFinding['fixAvailable'] = undefined;
  if (typeof vuln.fixAvailable === 'object') {
    fixAvailable = {
      version: vuln.fixAvailable.version,
      isBreaking: vuln.fixAvailable.isSemVerMajor,
    };
  }

  findings.push({
    id: uuidv4(),
    title,
    description: title, // npm audit doesn't provide separate description
    severity,
    interruptLevel,
    package: {
      name: packageName,
      version: vuln.range,
      ecosystem: 'npm',
    },
    vulnerability: {
      id: vulnIds[0] || 'UNKNOWN',
      aliases: vulnIds.slice(1),
    },
    depthLevel: depth,
    depChain: depChain.length > 0 ? depChain : undefined,
    isKEV: isKEVFlag,
    fixAvailable,
    metadata: {
      cvss,
      cwe: cwes.length > 0 ? cwes : undefined,
    },
    toolSource: 'npm-audit',
    foundAt: new Date(),
  });

  return findings;
}

/**
 * analyze_dependencies tool implementation
 */
export async function analyzeDependencies(args: any) {
  const { lockfile, projectPath }: AnalyzeDependenciesArgs = args;

  const session = requireSession();
  const repoPath = projectPath || session.project.path;

  const findings: DepFinding[] = [];
  const errors: string[] = [];

  // Detect lockfile if not provided
  let detectedLockfile = lockfile;
  if (!detectedLockfile) {
    detectedLockfile = detectLockfile(repoPath) || undefined;
    if (!detectedLockfile) {
      return {
        content: [
          {
            type: 'text',
            text:
              '❌ No lockfile detected in project.\n\n' +
              'Supported lockfiles:\n' +
              '  - package-lock.json, yarn.lock, pnpm-lock.yaml (Node.js)\n' +
              '  - requirements.txt, Pipfile.lock, poetry.lock (Python)\n' +
              '  - go.mod, go.sum (Go)\n' +
              '  - Cargo.lock (Rust)\n' +
              '  - composer.lock (PHP)\n' +
              '  - Gemfile.lock (Ruby)',
          },
        ],
        isError: true,
      };
    }
  }

  const ecosystem = getEcosystemFromLockfile(detectedLockfile);

  // Strategy 1: Try osv-scanner (universal)
  const hasOSVScanner = isOSVScannerInstalled();
  if (hasOSVScanner) {
    try {
      const osvResults = runOSVScanner(detectedLockfile, repoPath);
      osvResults.forEach((pkg) => {
        findings.push(...convertOSVToDepFindings(pkg, repoPath, ecosystem));
      });
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      errors.push(`osv-scanner: ${errorMsg}`);
    }
  }

  // Strategy 2: Fallback to npm audit for Node.js projects
  if (ecosystem === 'npm' && !hasOSVScanner) {
    const hasNpm = isNpmInstalled();
    if (hasNpm && hasPackageLock(repoPath)) {
      try {
        const npmResults = runNpmAudit(repoPath);
        Object.entries(npmResults).forEach(([pkgName, vuln]) => {
          findings.push(...convertNpmAuditToDepFinding(pkgName, vuln, repoPath));
        });
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        errors.push(`npm audit: ${errorMsg}`);
      }
    } else if (!hasNpm) {
      errors.push('Neither osv-scanner nor npm is installed');
    }
  }

  // If no tool available
  if (!hasOSVScanner && (ecosystem !== 'npm' || !isNpmInstalled())) {
    return {
      content: [
        {
          type: 'text',
          text:
            '❌ No dependency scanning tool available.\n\n' +
            'Please install osv-scanner (recommended for all ecosystems):\n' +
            '  macOS: brew install osv-scanner\n' +
            '  Linux: Download from https://github.com/google/osv-scanner/releases\n' +
            '  Go: go install github.com/google/osv-scanner/cmd/osv-scanner@latest',
        },
      ],
      isError: true,
    };
  }

  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  // Update session
  const existingCode = session.scanFindings?.code || [];
  updateScanFindings({
    code: existingCode, // preserve existing code findings
    deps: findings,
    scannedAt: new Date(),
  });

  // Format output
  const output: string[] = [];

  output.push('# Dependency Analysis (SCA)');
  output.push('');
  output.push(`📂 Project: ${repoPath}`);
  output.push(`📋 Lockfile: ${detectedLockfile}`);
  output.push(`🔧 Ecosystem: ${ecosystem}`);
  output.push('');

  // Tools used
  const toolsUsed: string[] = [];
  if (hasOSVScanner) toolsUsed.push('osv-scanner');
  if (ecosystem === 'npm' && !hasOSVScanner) toolsUsed.push('npm audit');
  output.push(`🛠️  Tools: ${toolsUsed.join(', ')}`);
  output.push('');

  // Errors
  if (errors.length > 0) {
    output.push('⚠️  **Warnings:**');
    errors.forEach((err) => output.push(`  - ${err}`));
    output.push('');
  }

  // Summary
  if (findings.length === 0) {
    output.push('✅ No known vulnerabilities detected!');
    output.push('');
    output.push('All dependencies are free of known security vulnerabilities.');
  } else {
    const criticalCount = findings.filter((f) => f.severity === 'critical').length;
    const highCount = findings.filter((f) => f.severity === 'high').length;
    const mediumCount = findings.filter((f) => f.severity === 'medium').length;
    const lowCount = findings.filter((f) => f.severity === 'low').length;

    const directCount = findings.filter((f) => f.depthLevel === 1).length;
    const transitiveCount = findings.filter((f) => f.depthLevel > 1).length;
    const kevCount = findings.filter((f) => f.isKEV).length;
    const fixableCount = findings.filter((f) => f.fixAvailable).length;

    output.push(`⚠️  Found ${findings.length} vulnerable dependencies:`);
    if (criticalCount > 0) output.push(`  - 🔴 Critical: ${criticalCount}`);
    if (highCount > 0) output.push(`  - 🟠 High: ${highCount}`);
    if (mediumCount > 0) output.push(`  - 🟡 Medium: ${mediumCount}`);
    if (lowCount > 0) output.push(`  - ⚪ Low: ${lowCount}`);
    output.push('');

    output.push(`📊 **Breakdown:**`);
    output.push(`  - Direct dependencies: ${directCount}`);
    output.push(`  - Transitive dependencies: ${transitiveCount}`);
    if (kevCount > 0) output.push(`  - ⚠️  CISA KEV (actively exploited): ${kevCount}`);
    output.push(`  - Fixable: ${fixableCount}/${findings.length}`);
    output.push('');

    // Show critical/high in detail
    const criticalAndHigh = findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
    if (criticalAndHigh.length > 0) {
      output.push('## 🔴 Critical & High Severity Vulnerabilities');
      output.push('');
      criticalAndHigh.forEach((finding) => {
        output.push(formatDepFinding(finding));
      });
    }

    // Summarize medium/low
    const medium = findings.filter((f) => f.severity === 'medium');
    const low = findings.filter((f) => f.severity === 'low');

    if (medium.length > 0) {
      output.push('## 🟡 Medium Severity Vulnerabilities');
      output.push('');
      medium.forEach((finding, i) => {
        output.push(
          `${i + 1}. **${finding.vulnerability.id}** in \`${finding.package.name}@${finding.package.version}\` - ${finding.title}`
        );
      });
      output.push('');
    }

    if (low.length > 0) {
      output.push('## ⚪ Low Severity Vulnerabilities');
      output.push(`${low.length} low severity vulnerabilities found. Run with verbose mode for details.`);
      output.push('');
    }

    // Next steps
    output.push('---');
    output.push('');
    output.push('**💡 Next Steps:**');
    if (kevCount > 0) {
      output.push('1. 🛑 **URGENT**: Address CISA KEV vulnerabilities immediately - actively exploited');
    }
    if (fixableCount > 0) {
      output.push(`${kevCount > 0 ? '2' : '1'}. Update ${fixableCount} fixable dependencies`);
    }
    if (transitiveCount > 0) {
      output.push(
        `- Review transitive dependencies (${transitiveCount} found) - may require updating parent packages`
      );
    }
    output.push('- Run `scan_code` to check for code vulnerabilities');
    output.push('- Run `generate_sbom` to document all dependencies');
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
