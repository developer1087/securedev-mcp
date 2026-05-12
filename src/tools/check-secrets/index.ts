/**
 * check_secrets tool - Secret scanning with Gitleaks
 */

import { v4 as uuidv4 } from 'uuid';
import { SecretFinding, SecretState } from '../../shared/types';
import { calculateInterruptLevel } from '../../shared/interrupt';
import { maskSecret } from '../../shared/formatter';
import { updateSecrets, requireSession } from '../../session/context';
import {
  scanWorkingTree,
  scanFullHistory,
  scanBranch,
  isGitleaksInstalled,
} from './gitleaks-history';
import { CheckSecretsArgs, GitleaksResult } from './types';
import { ProgressReporter } from '../../shared/progress';

/**
 * Generic rotation steps (not service-specific)
 */
function getGenericRotationSteps(secretType: string): string[] {
  return [
    'Generate new credential in target service',
    'Update application config with new value',
    'Verify application works with new credential',
    'Revoke old credential in target service',
  ];
}

/**
 * Determine secret state
 */
function determineSecretState(
  result: GitleaksResult,
  workingTreeResults: GitleaksResult[]
): SecretState {
  // Check if secret is in working tree
  const isInWorkingTree = workingTreeResults.some(
    (r) => r.Fingerprint === result.Fingerprint
  );

  if (isInWorkingTree) {
    return 'live';
  }

  // If not in working tree but in history
  return 'history';
}

/**
 * Convert Gitleaks result to SecretFinding
 */
function convertToSecretFinding(
  result: GitleaksResult,
  state: SecretState
): SecretFinding {
  const severity = state === 'live' ? 'critical' : 'high';
  const interruptLevel = calculateInterruptLevel(severity, {
    isLiveSecret: state === 'live',
  });

  return {
    id: uuidv4(),
    title: `${result.RuleID.replace(/-/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase())} Detected`,
    description:
      state === 'live'
        ? `Active ${result.RuleID} found in working tree. This credential is currently exposed and should be rotated immediately.`
        : `${result.RuleID} found in git history. While not in current working tree, this credential exists in git history and may be compromised.`,
    severity,
    interruptLevel,
    location: {
      file: result.File,
      line: result.StartLine,
      column: result.StartColumn,
    },
    secret: {
      type: result.RuleID,
      maskedValue: maskSecret(result.Secret),
      entropy: result.Entropy,
    },
    state,
    firstSeenCommit: result.Commit,
    lastSeenCommit: result.Commit,
    rotationSteps: getGenericRotationSteps(result.RuleID),
    toolSource: 'gitleaks',
    foundAt: new Date(),
    metadata: {
      references: [
        'https://github.com/gitleaks/gitleaks',
        'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password',
      ],
    },
  };
}

/**
 * Check secrets tool implementation
 */
export async function checkSecrets(args: any, progress: ProgressReporter) {
  const { scope = 'working', branch, projectPath }: CheckSecretsArgs = args;

  await progress.step(1, 3, 'Initializing secret scan...');

  // Check if gitleaks is installed
  if (!isGitleaksInstalled()) {
    return {
      content: [
        {
          type: 'text',
          text:
            '❌ Gitleaks is not installed.\n\n' +
            'Please install gitleaks:\n' +
            '  macOS: brew install gitleaks\n' +
            '  Windows: scoop install gitleaks\n' +
            '  Linux: https://github.com/gitleaks/gitleaks#installing',
        },
      ],
      isError: true,
    };
  }

  const session = requireSession();
  const repoPath = projectPath || session.project.path;

  try {
    let results: GitleaksResult[] = [];
    let workingTreeResults: GitleaksResult[] = [];

    await progress.step(2, 3, 'Scanning for secrets with Gitleaks...');

    // Always scan working tree first to determine state
    workingTreeResults = scanWorkingTree(repoPath);

    // Then scan based on scope
    if (scope === 'working') {
      results = workingTreeResults;
    } else if (scope === 'history') {
      results = scanFullHistory(repoPath);
    } else if (scope === 'branch') {
      if (!branch) {
        return {
          content: [
            {
              type: 'text',
              text: '❌ Branch name is required when scope=branch',
            },
          ],
          isError: true,
        };
      }
      results = scanBranch(repoPath, branch);
    }

    await progress.step(3, 3, 'Processing and formatting results...');

    // Convert to SecretFindings
    const findings: SecretFinding[] = results.map((result) => {
      const state = determineSecretState(result, workingTreeResults);
      return convertToSecretFinding(result, state);
    });

    // Update session
    updateSecrets({
      live: findings,
      scannedAt: new Date(),
    });

    // Format output
    const output: string[] = [];

    output.push('# Secret Scan Results');
    output.push('');
    output.push(`🔍 Scope: ${scope}`);
    output.push(`📂 Repository: ${repoPath}`);
    output.push('');

    if (findings.length === 0) {
      output.push('✅ No secrets detected!');
      output.push('');
      output.push('This is good news - no hardcoded credentials were found.');
    } else {
      const liveSecrets = findings.filter((f) => f.state === 'live');
      const historySecrets = findings.filter((f) => f.state === 'history');

      output.push(`⚠️  Found ${findings.length} secret(s):`);
      output.push(`  - 🔴 Live (in working tree): ${liveSecrets.length}`);
      output.push(`  - 📜 History only: ${historySecrets.length}`);
      output.push('');

      // Group by state
      if (liveSecrets.length > 0) {
        output.push('## 🔴 Live Secrets (CRITICAL)');
        output.push('');
        liveSecrets.forEach((finding, i) => {
          output.push(`### ${i + 1}. ${finding.title}`);
          output.push(`**Type:** ${finding.secret.type}`);
          output.push(`**Location:** \`${finding.location.file}:${finding.location.line}\``);
          output.push(`**Value:** \`${finding.secret.maskedValue}\``);
          output.push('');
          output.push('**⚠️  IMMEDIATE ACTION REQUIRED:**');
          finding.rotationSteps?.forEach((step, j) => {
            output.push(`${j + 1}. ${step}`);
          });
          output.push('');
        });
      }

      if (historySecrets.length > 0) {
        output.push('## 📜 Secrets in History');
        output.push('');
        output.push(
          'These secrets are not in the current working tree but exist in git history. ' +
          'They should still be rotated as the git history is public/accessible.'
        );
        output.push('');
        historySecrets.forEach((finding, i) => {
          output.push(`### ${i + 1}. ${finding.title}`);
          output.push(`**Type:** ${finding.secret.type}`);
          output.push(`**File:** \`${finding.location.file}\``);
          output.push(`**Commit:** ${finding.firstSeenCommit?.substring(0, 7)}`);
          output.push('');
        });
      }

      // Warning if repo is public
      output.push('---');
      output.push('');
      output.push('⚠️  **If this repository is public:**');
      output.push('- Assume all secrets in git history are compromised');
      output.push('- Check service logs for unauthorized access during exposure period');
      output.push('- Rotate ALL detected credentials immediately');
    }

    return {
      content: [
        {
          type: 'text',
          text: output.join('\n'),
        },
      ],
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [
        {
          type: 'text',
          text: `❌ Error scanning for secrets: ${errorMessage}`,
        },
      ],
      isError: true,
    };
  }
}
