/**
 * Types for analyze_dependencies tool
 */

export type Ecosystem = 'npm' | 'pip' | 'go' | 'maven' | 'nuget';

export interface AnalyzeDependenciesArgs {
  lockfile?: string;
  projectPath?: string;
}

// OSV-Scanner output types
export interface OSVPackage {
  package: {
    name: string;
    version: string;
    ecosystem: string;
  };
  vulnerabilities: OSVVulnerability[];
}

export interface OSVVulnerability {
  id: string; // CVE-2024-1234 or GHSA-xxxx
  aliases?: string[];
  summary?: string;
  details?: string;
  modified?: string;
  published?: string;
  severity?: Array<{
    type: string;
    score: string;
  }>;
  affected?: Array<{
    package: {
      ecosystem: string;
      name: string;
    };
    ranges?: Array<{
      type: string;
      events: Array<{
        introduced?: string;
        fixed?: string;
      }>;
    }>;
    database_specific?: {
      severity?: string;
    };
  }>;
  references?: Array<{
    type: string;
    url: string;
  }>;
  database_specific?: {
    cwe_ids?: string[];
    severity?: string;
    github_reviewed?: boolean;
  };
}

export interface OSVResult {
  results?: OSVPackage[];
}

// npm audit output types
export interface NpmAuditVulnerability {
  name: string;
  severity: 'info' | 'low' | 'moderate' | 'high' | 'critical';
  via: Array<string | {
    source: string;
    name: string;
    dependency: string;
    title: string;
    url: string;
    severity: string;
    cwe?: string[];
    cvss?: {
      score: number;
      vectorString: string;
    };
    range: string;
  }>;
  range: string;
  nodes: string[];
  fixAvailable: boolean | {
    name: string;
    version: string;
    isSemVerMajor: boolean;
  };
}

export interface NpmAuditOutput {
  vulnerabilities?: Record<string, NpmAuditVulnerability>;
  metadata?: {
    vulnerabilities: {
      info: number;
      low: number;
      moderate: number;
      high: number;
      critical: number;
      total: number;
    };
    dependencies: {
      prod: number;
      dev: number;
      optional: number;
      peer: number;
      peerOptional: number;
      total: number;
    };
  };
}
