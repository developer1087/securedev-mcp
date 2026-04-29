/**
 * Types for analyze_architecture tool
 */

import { Component } from '../../shared/types';

export interface AnalyzeArchitectureArgs {
  configFiles?: string[];
  projectPath?: string;
}

export interface DetectedComponent extends Component {
  detectedFrom: string; // which config file
  confidence: 'high' | 'medium' | 'low';
}

export interface DockerComposeService {
  image?: string;
  build?: string | { context: string };
  ports?: Array<string | { target: number; published: number }>;
  environment?: Record<string, string> | string[];
  networks?: string[] | Record<string, any>;
  depends_on?: string[] | Record<string, any>;
  volumes?: string[];
  command?: string | string[];
}

export interface DockerCompose {
  version?: string;
  services?: Record<string, DockerComposeService>;
  networks?: Record<string, any>;
  volumes?: Record<string, any>;
}
