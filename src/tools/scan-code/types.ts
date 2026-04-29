/**
 * Types for scan_code tool
 */

export type ProjectType = 'web-app' | 'api' | 'cli' | 'library';

export interface ScanCodeArgs {
  files?: string[];
  projectType?: ProjectType;
  projectPath?: string;
}

// Semgrep output types
export interface SemgrepResult {
  check_id: string;
  path: string;
  start: {
    line: number;
    col: number;
  };
  end: {
    line: number;
    col: number;
  };
  extra: {
    message: string;
    metadata?: {
      category?: string;
      cwe?: string[];
      owasp?: string[];
      confidence?: string;
      likelihood?: string;
      impact?: string;
      subcategory?: string[];
    };
    severity: 'ERROR' | 'WARNING' | 'INFO';
    fingerprint?: string;
  };
}

export interface SemgrepOutput {
  results?: SemgrepResult[];
  errors?: Array<{
    message: string;
    path?: string;
  }>;
}
