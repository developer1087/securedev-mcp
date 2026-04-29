/**
 * Shared types for SecureDev MCP
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type InterruptLevel = 'hard_stop' | 'action_required' | 'monitor';
export type StrideCategory = 'spoofing' | 'tampering' | 'repudiation' | 'information_disclosure' | 'denial_of_service' | 'elevation_of_privilege';
export type SecretState = 'live' | 'history' | 'branch_only';

// Base Finding interface
export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  interruptLevel: InterruptLevel;
  location: {
    file: string;
    line?: number;
    column?: number;
  };
  metadata?: {
    cwe?: string[];
    cvss?: number;
    cvssVector?: string;
    owasp?: string[];
    references?: string[];
    hasActivePoc?: boolean;
  };
  toolSource: 'semgrep' | 'gitleaks' | 'osv-scanner' | 'npm-audit' | 'manual' | 'llm';
  foundAt: Date;
}

// Dependency Finding
export interface DepFinding extends Omit<Finding, 'location'> {
  package: {
    name: string;
    version: string;
    ecosystem: 'npm' | 'pip' | 'go' | 'maven' | 'nuget';
  };
  vulnerability: {
    id: string; // CVE-2024-1234 or GHSA-xxxx
    aliases: string[];
    publishedAt?: Date;
    lastModified?: Date;
  };
  depthLevel: number; // 1 = direct, 2+ = transitive
  depChain?: string[]; // dependency chain from root to vulnerable package
  isKEV?: boolean; // CISA Known Exploited Vulnerabilities
  fixAvailable?: {
    version: string;
    isBreaking: boolean;
  };
}

// Architecture Finding
export interface ArchFinding extends Omit<Finding, 'location'> {
  strideCategory?: StrideCategory;
  affectedComponents: string[];
  nistControl?: string;
  mitigations: string[];
  detectionMethod: 'rule' | 'llm' | 'hybrid';
}

// Secret Finding
export interface SecretFinding extends Finding {
  secret: {
    type: string; // 'aws-access-token', 'generic-api-key', etc.
    maskedValue: string; // ••••last4
    entropy?: number;
  };
  state: SecretState;
  firstSeenCommit?: string;
  lastSeenCommit?: string;
  rotationSteps?: string[];
}

// Threat Model Finding
export interface ThreatModelFinding {
  id: string;
  featureId: string;
  title: string;
  description: string;
  strideCategory: StrideCategory;
  severity: Severity;
  mitigations: string[]; // actionable steps
  likelihood?: 'low' | 'medium' | 'high';
  impact?: 'low' | 'medium' | 'high';
  metadata?: {
    cwe?: string[];
    cvssVector?: string;
    references?: string[];
  };
}

// Feature (for threat modeling)
export interface Feature {
  id: string;
  name: string;
  description: string;
  context: {
    accessControl: 'public' | 'authenticated' | 'admin';
    dataVisibility: 'public' | 'friends' | 'private';
    storage: 'db' | 'file' | 'cloud' | 'memory';
    hasProcessing: boolean;
    processingType?: string;
  };
  threats: ThreatModelFinding[];
}

// Component (for architecture analysis)
export interface Component {
  name: string;
  type: 'service' | 'database' | 'cache' | 'queue' | 'api' | 'frontend' | 'proxy';
  technology?: string; // 'redis', 'postgres', 'nginx', etc.
  ports?: number[];
  environment?: Record<string, string>;
  network?: string;
  dependencies?: string[]; // other component names
  routes?: {
    path: string;
    methods: string[];
    middleware?: string[];
  }[];
}

// Package (for SBOM)
export interface Package {
  name: string;
  version: string;
  ecosystem: 'npm' | 'pip' | 'go' | 'maven' | 'nuget';
  license?: string;
  depth: number; // 1 = direct, 2+ = transitive
  homepage?: string;
  repository?: string;
  isEOL?: boolean;
  eolDate?: Date;
  isUnmaintained?: boolean;
  lastCommitDate?: Date;
}

// License Issue
export interface LicenseIssue {
  license: string;
  reason: string;
  packages: string[];
  severity: 'high' | 'medium' | 'low';
  recommendation: string;
}

// Session Context
export interface SessionContext {
  project: {
    name: string;
    path: string;
    stack: string[]; // ['typescript', 'react', 'node', 'postgres']
    entrypoints: string[];
    isPublicFacing: boolean;
    hasPayments: boolean;
  };
  threatModel?: {
    features: Feature[];
    threats: ThreatModelFinding[];
    savedAt: Date;
  };
  scanFindings?: {
    code: Finding[];
    deps: DepFinding[];
    scannedAt: Date;
  };
  architecture?: {
    components: Component[];
    threats: ArchFinding[];
    analyzedAt: Date;
  };
  secrets?: {
    live: SecretFinding[];
    scannedAt: Date;
  };
  sbom?: {
    packages: Package[];
    licenseIssues: LicenseIssue[];
    generatedAt: Date;
  };
}

// Guidance Response
export interface GuidanceResponse {
  responseType: 'answer' | 'push_suggestion' | 'escalate';
  content: string;
  codeExample?: string;
  references?: string[]; // ['CWE-89', 'OWASP A03:2021']
  followUpSuggestions?: string[];
  escalationReason?: string;
  escalationAlternative?: string;
}

// Delta Report
export interface DeltaReport {
  misses: Array<{
    threat: ThreatModelFinding;
    reason: string;
  }>;
  ok: Array<{
    threat: ThreatModelFinding;
    mitigatedBy: Finding | DepFinding | ArchFinding;
  }>;
  new: Array<Finding | DepFinding | ArchFinding>;
}

// Score Breakdown
export interface ScoreBreakdown {
  total: number;
  breakdown: {
    criticalFindings: { count: number; impact: number };
    highFindings: { count: number; impact: number };
    mediumFindings: { count: number; impact: number };
    lowFindings: { count: number; impact: number };
    deltaMisses: { count: number; impact: number };
    liveSecrets: { count: number; impact: number };
    toolsRun: { count: number; bonus: number };
  };
}
