/**
 * Semgrep scanner for SAST
 */

import { execSync } from 'child_process';
import { existsSync } from 'fs';
import { SemgrepOutput, SemgrepResult, ProjectType } from './types';

/**
 * Resolve a semgrep command we can execute.
 *
 * Some environments (like IDE sandboxes) don't include the user Python bin
 * directory on PATH, even when `pip install --user semgrep` succeeded.
 */
function resolveSemgrepCommand(): string | null {
  try {
    execSync('semgrep --version', { stdio: 'pipe' });
    return 'semgrep';
  } catch {}

  // Fallback to Python module invocation (works when semgrep is installed but
  // the shim isn't on PATH).
  try {
    execSync('python3 -m semgrep --version', { stdio: 'pipe' });
    return 'python3 -m semgrep';
  } catch {}

  return null;
}

/**
 * Check if semgrep is installed
 */
export function isSemgrepInstalled(): boolean {
  return resolveSemgrepCommand() !== null;
}

/**
 * Get additional config rules based on project type
 */
function getProjectTypeConfig(projectType?: ProjectType): string[] {
  const configs: string[] = [];

  switch (projectType) {
    case 'web-app':
      configs.push('p/xss', 'p/sql-injection', 'p/command-injection');
      break;
    case 'api':
      configs.push('p/jwt', 'p/insecure-transport', 'p/sql-injection');
      break;
    case 'cli':
      configs.push('p/command-injection', 'p/insecure-transport');
      break;
    case 'library':
      configs.push('p/insecure-transport', 'p/crypto');
      break;
  }

  return configs;
}

/**
 * Run semgrep on specified files/directories
 */
export function runSemgrep(
  files: string[],
  projectPath: string,
  projectType?: ProjectType
): SemgrepResult[] {
  const semgrepCmd = resolveSemgrepCommand();
  if (!semgrepCmd) {
    throw new Error(
      'Semgrep is not installed. Please install it:\n' +
      '  macOS: brew install semgrep\n' +
      '  Linux: pip install semgrep\n' +
      '  Windows: pip install semgrep'
    );
  }

  // Validate files exist
  const validFiles = files.filter((file) => {
    const fullPath = file.startsWith('/') ? file : `${projectPath}/${file}`;
    return existsSync(fullPath);
  });

  if (validFiles.length === 0) {
    // Default to scanning the whole project
    validFiles.push('.');
  }

  // Build config arguments
  const configs = ['auto', 'p/security-audit', ...getProjectTypeConfig(projectType)];
  const configArgs = configs.map((c) => `--config=${c}`).join(' ');

  // Build file arguments
  const fileArgs = validFiles.join(' ');

  try {
    // Run semgrep
    // Note: semgrep exits with code 1 if findings are found, which is expected
    let output: string;
    try {
      output = execSync(
        `cd "${projectPath}" && ${semgrepCmd} ${configArgs} --json ${fileArgs}`,
        {
          stdio: 'pipe',
          encoding: 'utf-8',
          maxBuffer: 10 * 1024 * 1024, // 10MB buffer for large codebases
        }
      );
    } catch (error: any) {
      // Exit code 1 means findings were found - this is OK
      // Exit code 2+ means actual error
      if (error.status && error.status === 1 && error.stdout) {
        output = error.stdout;
      } else if (error.status && error.status > 1) {
        throw new Error(`Semgrep error (exit ${error.status}): ${error.stderr || error.message}`);
      } else {
        throw error;
      }
    }

    // Parse JSON output
    const parsed: SemgrepOutput = JSON.parse(output);

    // Log errors if any
    if (parsed.errors && parsed.errors.length > 0) {
      console.warn('Semgrep encountered errors:');
      parsed.errors.forEach((err) => {
        console.warn(`  - ${err.path || 'unknown'}: ${err.message}`);
      });
    }

    return parsed.results || [];
  } catch (error) {
    if (error instanceof Error && error.message.includes('not installed')) {
      throw error;
    }
    throw new Error(`Semgrep scan failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Map Semgrep severity to our severity levels
 */
export function mapSemgrepSeverity(
  semgrepSeverity: 'ERROR' | 'WARNING' | 'INFO'
): 'critical' | 'high' | 'medium' | 'low' {
  switch (semgrepSeverity) {
    case 'ERROR':
      return 'critical';
    case 'WARNING':
      return 'high';
    case 'INFO':
      return 'medium';
    default:
      return 'low';
  }
}
