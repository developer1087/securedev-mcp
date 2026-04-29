/**
 * Session context management - in-memory store
 */

import { SessionContext } from '../shared/types';

/**
 * In-memory session store
 * Phase 1: Single session per process
 * Phase 2: Multi-session with persistence
 */
let currentSession: SessionContext | null = null;

/**
 * Initialize a new session
 */
export function initSession(projectPath: string, projectName: string): SessionContext {
  currentSession = {
    project: {
      name: projectName,
      path: projectPath,
      stack: [],
      entrypoints: [],
      isPublicFacing: false,
      hasPayments: false,
    },
  };

  return currentSession;
}

/**
 * Get current session
 */
export function getSession(): SessionContext | null {
  return currentSession;
}

/**
 * Require session to exist (throw if not)
 */
export function requireSession(): SessionContext {
  if (!currentSession) {
    throw new Error(
      'No active session. Please initialize a session first by running any tool.'
    );
  }
  return currentSession;
}

/**
 * Update project metadata
 */
export function updateProjectMetadata(updates: Partial<SessionContext['project']>): void {
  const session = requireSession();
  session.project = {
    ...session.project,
    ...updates,
  };
}

/**
 * Update threat model
 */
export function updateThreatModel(update: SessionContext['threatModel']): void {
  const session = requireSession();
  session.threatModel = update;
}

/**
 * Update scan findings
 */
export function updateScanFindings(update: SessionContext['scanFindings']): void {
  const session = requireSession();
  session.scanFindings = update;
}

/**
 * Update architecture analysis
 */
export function updateArchitecture(update: SessionContext['architecture']): void {
  const session = requireSession();
  session.architecture = update;
}

/**
 * Update secrets findings
 */
export function updateSecrets(update: SessionContext['secrets']): void {
  const session = requireSession();
  session.secrets = update;
}

/**
 * Update SBOM
 */
export function updateSBOM(update: SessionContext['sbom']): void {
  const session = requireSession();
  session.sbom = update;
}

/**
 * Clear session
 */
export function clearSession(): void {
  currentSession = null;
}

/**
 * Check if session exists
 */
export function hasSession(): boolean {
  return currentSession !== null;
}

/**
 * Get session summary for display
 */
export function getSessionSummary(): {
  project: string;
  toolsRun: string[];
  totalFindings: number;
  criticalFindings: number;
} {
  const session = requireSession();

  const toolsRun: string[] = [];
  let totalFindings = 0;
  let criticalFindings = 0;

  if (session.scanFindings) {
    toolsRun.push('scan_code', 'analyze_dependencies');
    totalFindings += session.scanFindings.code.length + session.scanFindings.deps.length;
    criticalFindings += session.scanFindings.code.filter((f) => f.severity === 'critical').length;
    criticalFindings += session.scanFindings.deps.filter((f) => f.severity === 'critical').length;
  }

  if (session.architecture) {
    toolsRun.push('analyze_architecture');
    totalFindings += session.architecture.threats.length;
    criticalFindings += session.architecture.threats.filter((f) => f.severity === 'critical').length;
  }

  if (session.threatModel) {
    toolsRun.push('threat_model');
  }

  if (session.secrets) {
    toolsRun.push('check_secrets');
    totalFindings += session.secrets.live.length;
    criticalFindings += session.secrets.live.filter((f) => f.severity === 'critical').length;
  }

  if (session.sbom) {
    toolsRun.push('generate_sbom');
  }

  return {
    project: session.project.name,
    toolsRun,
    totalFindings,
    criticalFindings,
  };
}

/**
 * Export session as JSON (for debugging or future persistence)
 */
export function exportSession(): string {
  const session = requireSession();
  return JSON.stringify(session, null, 2);
}

/**
 * Import session from JSON (for future persistence)
 */
export function importSession(json: string): SessionContext {
  try {
    const parsed = JSON.parse(json) as SessionContext;

    // Convert date strings back to Date objects
    if (parsed.threatModel?.savedAt) {
      parsed.threatModel.savedAt = new Date(parsed.threatModel.savedAt);
    }
    if (parsed.scanFindings?.scannedAt) {
      parsed.scanFindings.scannedAt = new Date(parsed.scanFindings.scannedAt);
    }
    if (parsed.architecture?.analyzedAt) {
      parsed.architecture.analyzedAt = new Date(parsed.architecture.analyzedAt);
    }
    if (parsed.secrets?.scannedAt) {
      parsed.secrets.scannedAt = new Date(parsed.secrets.scannedAt);
    }
    if (parsed.sbom?.generatedAt) {
      parsed.sbom.generatedAt = new Date(parsed.sbom.generatedAt);
    }

    currentSession = parsed;
    return parsed;
  } catch (error) {
    throw new Error(`Failed to import session: ${error}`);
  }
}
