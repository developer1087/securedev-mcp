/**
 * Progress reporting helper for long-running tools
 * Wraps MCP progress notifications
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';

export interface ProgressUpdate {
  message: string;
  progress: number;
  total?: number;
}

/**
 * ProgressReporter - Helper class to send progress updates to MCP client
 */
export class ProgressReporter {
  private server: Server | null;
  private progressToken: string | undefined;
  private lastProgress: number = 0;

  constructor(server: Server | null, progressToken: string | undefined) {
    this.server = server;
    this.progressToken = progressToken;
  }

  /**
   * Report progress update to client
   */
  async report(update: ProgressUpdate): Promise<void> {
    // Skip if no server or token
    if (!this.server || !this.progressToken) {
      return;
    }

    // Ensure progress increases
    if (update.progress < this.lastProgress) {
      return;
    }

    this.lastProgress = update.progress;

    // Send notification via MCP
    try {
      await this.server.notification({
        method: 'notifications/progress',
        params: {
          progressToken: this.progressToken,
          progress: update.progress,
          total: update.total,
          message: update.message,
        },
      });
    } catch (error) {
      // Silently ignore errors (client may not support progress)
      console.error('Progress notification error:', error);
    }
  }

  /**
   * Report step completion (for multi-step operations)
   */
  async step(stepNumber: number, totalSteps: number, message: string): Promise<void> {
    await this.report({
      progress: stepNumber,
      total: totalSteps,
      message: `[${stepNumber}/${totalSteps}] ${message}`,
    });
  }

  /**
   * Report percentage-based progress
   */
  async percent(percentage: number, message: string): Promise<void> {
    await this.report({
      progress: percentage,
      total: 100,
      message: `${message} (${percentage}%)`,
    });
  }

  /**
   * Check if progress reporting is enabled
   */
  isEnabled(): boolean {
    return !!(this.server && this.progressToken);
  }
}

/**
 * Create a no-op progress reporter (for when progress token is not available)
 */
export function createNoOpReporter(): ProgressReporter {
  return new ProgressReporter(null, undefined);
}
