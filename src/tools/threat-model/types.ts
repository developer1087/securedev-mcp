/**
 * Types for threat_model tool
 */

export interface ThreatModelArgs {
  featureDescription: string;
  clarifications?: {
    accessControl?: 'public' | 'authenticated' | 'admin';
    dataVisibility?: 'public' | 'friends' | 'private';
    storage?: 'db' | 'file' | 'cloud' | 'memory';
    processingType?: string;
  };
  projectPath?: string;
}

export interface ClarifyingQuestions {
  questions: Array<{
    id: string;
    question: string;
    options: string[];
  }>;
}

export interface StrideAnalysisResponse {
  threats: Array<{
    strideCategory: string;
    title: string;
    description: string;
    severity: string;
    likelihood: string;
    impact: string;
    mitigations: string[];
    cwe?: string[];
    cvssVector?: string;
    references?: string[];
  }>;
  notApplicable?: Array<{
    strideCategory: string;
    reason: string;
  }>;
}
