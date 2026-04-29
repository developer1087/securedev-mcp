/**
 * Types for generate_sbom tool
 */

export type SBOMFormat = 'cyclonedx-json' | 'cyclonedx-xml' | 'spdx-json';
export type LicenseStatus = 'ok' | 'review' | 'restricted';

export interface GenerateSBOMArgs {
  format?: SBOMFormat;
  outputPath?: string;
  projectPath?: string;
}

export interface PackageInfo {
  name: string;
  version: string;
  ecosystem: 'npm' | 'pip' | 'go' | 'maven' | 'nuget';
  license?: string;
  depth: number; // 1 = direct, 2+ = transitive
  homepage?: string;
  repository?: string;
  description?: string;
  author?: string;
  isEOL?: boolean;
  eolDate?: Date;
  isUnmaintained?: boolean;
  lastCommitDate?: Date;
}

export interface LicenseAnalysis {
  license: string;
  status: LicenseStatus;
  packages: string[];
  reason?: string;
  recommendation?: string;
}

export interface SBOMSummary {
  totalPackages: number;
  directPackages: number;
  transitivePackages: number;
  licenseBreakdown: Array<{
    license: string;
    count: number;
    status: LicenseStatus;
  }>;
  licenseIssues: LicenseAnalysis[];
  eolPackages: Array<{
    package: string;
    eolDate?: Date;
    currentVersion: string;
  }>;
  unmaintainedPackages: Array<{
    package: string;
    lastCommit?: Date;
  }>;
}
