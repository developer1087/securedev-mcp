/**
 * Types for get_guidance tool
 */

export interface GetGuidanceArgs {
  question: string;
  mode?: 'answer' | 'push';
  projectPath?: string;
}

export interface GuidancePromptContext {
  projectName: string;
  stack: string[];
  components?: string[];
  recentFindings?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  threatModelExists: boolean;
  secretsFound: boolean;
}
