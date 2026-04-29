/**
 * Types for check_secrets tool
 */

export interface GitleaksResult {
  Description: string;
  StartLine: number;
  EndLine: number;
  StartColumn: number;
  EndColumn: number;
  Match: string;
  Secret: string;
  File: string;
  SymlinkFile: string;
  Commit: string;
  Entropy: number;
  Author: string;
  Email: string;
  Date: string;
  Message: string;
  Tags: string[];
  RuleID: string;
  Fingerprint: string;
}

export interface GitleaksOutput {
  results?: GitleaksResult[];
}

export interface CheckSecretsArgs {
  scope?: 'working' | 'history' | 'branch';
  branch?: string;
  projectPath?: string;
}
