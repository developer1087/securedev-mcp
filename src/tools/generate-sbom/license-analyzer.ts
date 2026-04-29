/**
 * License analyzer - flag problematic licenses
 */

import { PackageInfo, LicenseAnalysis, LicenseStatus } from './types';

/**
 * Get license status based on license identifier
 */
export function getLicenseStatus(license: string): LicenseStatus {
  const normalized = license.toLowerCase();

  // Copyleft licenses - require review
  if (
    normalized.includes('gpl-3.0') ||
    normalized.includes('gpl-2.0') ||
    normalized.includes('lgpl-2.1') ||
    normalized.includes('lgpl-3.0')
  ) {
    return 'review';
  }

  // AGPL - more restrictive, especially for SaaS
  if (normalized.includes('agpl-3.0') || normalized.includes('agpl')) {
    return 'restricted';
  }

  // Permissive licenses - OK
  if (
    normalized.includes('mit') ||
    normalized.includes('isc') ||
    normalized.includes('apache') ||
    normalized.includes('bsd') ||
    normalized.includes('0bsd') ||
    normalized.includes('unlicense')
  ) {
    return 'ok';
  }

  // Unknown or custom - review
  return 'review';
}

/**
 * Get human-readable reason for license flag
 */
function getLicenseReason(license: string): string {
  const normalized = license.toLowerCase();

  if (normalized.includes('agpl')) {
    return 'AGPL requires source code disclosure for network use (SaaS). Highly restrictive for web services.';
  }

  if (normalized.includes('gpl-3.0') || normalized.includes('gpl-2.0')) {
    return 'GPL requires derivative works to be open-sourced under same license (copyleft).';
  }

  if (normalized.includes('lgpl')) {
    return 'LGPL allows dynamic linking but requires disclosure of LGPL library modifications.';
  }

  if (!license || license === 'UNLICENSED' || license === 'UNKNOWN') {
    return 'No license information available - usage rights unclear.';
  }

  return 'Non-standard or custom license - requires legal review.';
}

/**
 * Get recommendation for problematic license
 */
function getLicenseRecommendation(license: string): string {
  const normalized = license.toLowerCase();

  if (normalized.includes('agpl')) {
    return 'Consult legal counsel before using in SaaS/commercial product. Consider alternative libraries.';
  }

  if (normalized.includes('gpl')) {
    return 'Consult legal counsel. May require open-sourcing your code. Consider LGPL or permissive alternatives.';
  }

  if (normalized.includes('lgpl')) {
    return 'Generally safe for dynamic linking. Ensure you can disclose modifications to the library itself.';
  }

  return 'Review license terms with legal counsel before production use.';
}

/**
 * Analyze licenses across all packages
 */
export function analyzeLicenses(packages: PackageInfo[]): {
  breakdown: Map<string, { count: number; status: LicenseStatus }>;
  issues: LicenseAnalysis[];
} {
  const licenseMap = new Map<string, { count: number; status: LicenseStatus; packages: string[] }>();

  // Count licenses
  for (const pkg of packages) {
    const license = pkg.license || 'UNKNOWN';
    const status = getLicenseStatus(license);

    if (!licenseMap.has(license)) {
      licenseMap.set(license, { count: 0, status, packages: [] });
    }

    const entry = licenseMap.get(license)!;
    entry.count++;
    entry.packages.push(pkg.name);
  }

  // Build breakdown
  const breakdown = new Map<string, { count: number; status: LicenseStatus }>();
  for (const [license, data] of licenseMap.entries()) {
    breakdown.set(license, { count: data.count, status: data.status });
  }

  // Build issues list (only review/restricted)
  const issues: LicenseAnalysis[] = [];
  for (const [license, data] of licenseMap.entries()) {
    if (data.status !== 'ok') {
      issues.push({
        license,
        status: data.status,
        packages: data.packages,
        reason: getLicenseReason(license),
        recommendation: getLicenseRecommendation(license),
      });
    }
  }

  // Sort issues by severity (restricted first, then review)
  issues.sort((a, b) => {
    if (a.status === 'restricted' && b.status !== 'restricted') return -1;
    if (a.status !== 'restricted' && b.status === 'restricted') return 1;
    return 0;
  });

  return { breakdown, issues };
}
