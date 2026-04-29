#!/usr/bin/env node

/**
 * SecureDev MCP Server
 * Entry point for the MCP server
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import { initSession, hasSession, getSession } from './session/context.js';
import { checkSecrets } from './tools/check-secrets/index.js';

// Tool stubs (to be implemented)
async function scanCodeStub(args: any) {
  return {
    content: [
      {
        type: 'text',
        text: 'scan_code tool - not yet implemented',
      },
    ],
  };
}

async function analyzeDependenciesStub(args: any) {
  return {
    content: [
      {
        type: 'text',
        text: 'analyze_dependencies tool - not yet implemented',
      },
    ],
  };
}

async function analyzeArchitectureStub(args: any) {
  return {
    content: [
      {
        type: 'text',
        text: 'analyze_architecture tool - not yet implemented',
      },
    ],
  };
}

async function threatModelStub(args: any) {
  return {
    content: [
      {
        type: 'text',
        text: 'threat_model tool - not yet implemented',
      },
    ],
  };
}

async function generateSBOMStub(args: any) {
  return {
    content: [
      {
        type: 'text',
        text: 'generate_sbom tool - not yet implemented',
      },
    ],
  };
}

async function getGuidanceStub(args: any) {
  return {
    content: [
      {
        type: 'text',
        text: 'get_guidance tool - not yet implemented',
      },
    ],
  };
}

/**
 * Auto-initialize session if needed
 */
function ensureSession(projectPath?: string) {
  if (!hasSession()) {
    const path = projectPath || process.cwd();
    const name = path.split('/').pop() || 'unknown';
    initSession(path, name);
  }
  return getSession()!;
}

/**
 * Create and configure MCP server
 */
async function main() {
  const server = new Server(
    {
      name: 'securedev-mcp',
      version: '0.1.0',
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  /**
   * List available tools
   */
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: [
        {
          name: 'scan_code',
          description:
            'SAST-light: Scan code for security vulnerabilities using Semgrep and Gitleaks (working tree). ' +
            'Detects common security issues like SQL injection, XSS, hardcoded secrets, and more.',
          inputSchema: {
            type: 'object',
            properties: {
              files: {
                type: 'array',
                items: { type: 'string' },
                description: 'Files or directories to scan (default: current directory)',
              },
              projectType: {
                type: 'string',
                enum: ['web-app', 'api', 'cli', 'library'],
                description: 'Type of project (helps tune rules)',
              },
            },
          },
        },
        {
          name: 'analyze_dependencies',
          description:
            'SCA: Analyze dependencies for known vulnerabilities using osv-scanner and npm audit. ' +
            'Checks both direct and transitive dependencies against CVE/GHSA databases.',
          inputSchema: {
            type: 'object',
            properties: {
              lockfile: {
                type: 'string',
                description: 'Path to lockfile (package-lock.json, yarn.lock, etc.)',
              },
            },
          },
        },
        {
          name: 'analyze_architecture',
          description:
            'Architecture security analysis: Detect components from config files and identify ' +
            'architectural security threats using Claude API + deterministic rules (STRIDE framework).',
          inputSchema: {
            type: 'object',
            properties: {
              configFiles: {
                type: 'array',
                items: { type: 'string' },
                description: 'Config files to analyze (docker-compose.yml, nginx.conf, etc.)',
              },
            },
          },
        },
        {
          name: 'threat_model',
          description:
            'Proactive threat modeling: Create STRIDE threat model for a feature before implementation. ' +
            'Asks clarifying questions, then generates baseline threats to compare against actual findings.',
          inputSchema: {
            type: 'object',
            properties: {
              featureDescription: {
                type: 'string',
                description: 'Free-text description of the feature to model',
              },
              clarifications: {
                type: 'object',
                description: 'Answers to clarifying questions (if re-running)',
              },
            },
            required: ['featureDescription'],
          },
        },
        {
          name: 'check_secrets',
          description:
            'Secret scanning: Scan git repository for leaked secrets using Gitleaks. ' +
            'Can scan working tree, full history, or specific branch. Detects API keys, passwords, tokens, etc.',
          inputSchema: {
            type: 'object',
            properties: {
              scope: {
                type: 'string',
                enum: ['working', 'history', 'branch'],
                description: 'Scan scope: working tree only, full history, or specific branch',
                default: 'working',
              },
              branch: {
                type: 'string',
                description: 'Branch name (required if scope=branch)',
              },
              projectPath: {
                type: 'string',
                description: 'Path to git repository (default: current directory)',
              },
            },
          },
        },
        {
          name: 'generate_sbom',
          description:
            'Generate Software Bill of Materials (SBOM) in CycloneDX or SPDX format. ' +
            'Includes license analysis, EOL detection, and unmaintained package checks.',
          inputSchema: {
            type: 'object',
            properties: {
              format: {
                type: 'string',
                enum: ['cyclonedx-json', 'cyclonedx-xml', 'spdx-json'],
                description: 'SBOM format',
                default: 'cyclonedx-json',
              },
              outputPath: {
                type: 'string',
                description: 'Output file path',
              },
            },
          },
        },
        {
          name: 'get_guidance',
          description:
            'Security guidance: Ask security questions and get contextual advice based on your project. ' +
            'Uses Claude API with full session context. Can also provide proactive suggestions after tool runs.',
          inputSchema: {
            type: 'object',
            properties: {
              question: {
                type: 'string',
                description: 'Security question or topic',
              },
              mode: {
                type: 'string',
                enum: ['answer', 'push'],
                description: 'Mode: answer (user question) or push (proactive suggestion)',
                default: 'answer',
              },
            },
            required: ['question'],
          },
        },
      ],
    };
  });

  /**
   * Handle tool calls
   */
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
      // Ensure session exists
      ensureSession((args as any)?.projectPath);

      switch (name) {
        case 'scan_code':
          return await scanCodeStub(args);

        case 'analyze_dependencies':
          return await analyzeDependenciesStub(args);

        case 'analyze_architecture':
          return await analyzeArchitectureStub(args);

        case 'threat_model':
          return await threatModelStub(args);

        case 'check_secrets':
          return await checkSecrets(args);

        case 'generate_sbom':
          return await generateSBOMStub(args);

        case 'get_guidance':
          return await getGuidanceStub(args);

        default:
          return {
            content: [
              {
                type: 'text',
                text: `Unknown tool: ${name}`,
              },
            ],
            isError: true,
          };
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        content: [
          {
            type: 'text',
            text: `Error executing ${name}: ${errorMessage}`,
          },
        ],
        isError: true,
      };
    }
  });

  /**
   * Start server
   */
  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error('SecureDev MCP server running on stdio');
}

// Run server
main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
