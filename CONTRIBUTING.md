# Contributing to SecureDev MCP

Thank you for your interest in contributing! 🎉

## Quick Start

1. Fork this repository
2. Clone your fork: `git clone https://github.com/YOUR-USERNAME/securedev-mcp.git`
3. Create a branch: `git checkout -b your-feature-name`
4. Make your changes
5. Test your changes (see below)
6. Commit: `git commit -m "Description of changes"`
7. Push: `git push origin your-feature-name`
8. Open a Pull Request

## Development Setup

```bash
# Install dependencies
npm install

# Build the project
npm run build

# Watch mode (rebuilds on file changes)
npm run watch

# Run with ts-node (for quick testing)
npm run dev
```

## Project Structure

- `src/index.ts` - MCP server entry point
- `src/tools/` - The 7 security tools (each in its own directory)
- `src/shared/` - Shared utilities (types, formatters, progress, etc.)
- `src/session/` - Session management and security scoring

## Testing Your Changes

### Manual Testing with Cursor

1. Build: `npm run build`
2. Make sure your `~/.cursor/mcp.json` points to your local build:
   ```json
   {
     "mcpServers": {
       "securedev": {
         "command": "node",
         "args": ["/path/to/your/securedev-mcp/dist/index.js"],
         "env": {
           "ANTHROPIC_API_KEY": "your-key"
         }
       }
     }
   }
   ```
3. Restart Cursor
4. Test the tool in Cursor's chat

### Quick Smoke Test

```bash
# Build and check for compilation errors
npm run build

# Test that the server starts
node dist/index.js
# Should print: "SecureDev MCP server running on stdio"
# Press Ctrl+C to exit
```

## Code Style

- Use TypeScript
- Follow existing patterns in the codebase
- Add comments for complex logic
- Keep functions focused and small

## Adding a New Tool

1. Create a new directory: `src/tools/your-tool/`
2. Add these files:
   - `index.ts` - Main tool implementation
   - `types.ts` - TypeScript interfaces
   - `CLAUDE.md` - Documentation for the tool
3. Register the tool in `src/index.ts`:
   ```typescript
   import { yourTool } from './tools/your-tool/index.js';

   // Add to ListToolsRequestSchema handler
   // Add to CallToolRequestSchema handler switch statement
   ```
4. Add progress reporting (see `src/shared/progress.ts`)
5. Update `README.md` with the new tool

## Improving Existing Tools

When modifying a tool:

1. Read the tool's `CLAUDE.md` file first (explains the design)
2. Maintain backward compatibility if possible
3. Update the `CLAUDE.md` if you change behavior
4. Test with real projects, not just toy examples

## Progress Reporting Guidelines

All tools should report progress at key milestones:

```typescript
export async function myTool(args: any, progress: ProgressReporter) {
  await progress.step(1, 4, 'Initializing...');
  // do work
  await progress.step(2, 4, 'Scanning files...');
  // do work
  await progress.step(3, 4, 'Analyzing results...');
  // do work
  await progress.step(4, 4, 'Formatting output...');
  // return results
}
```

## Output Formatting

Follow these principles:

- **Title**: Professional security term (e.g., "SQL Injection", not "Database attack")
- **Description**: Technical but clear explanation
- **Severity**: critical / high / medium / low
- **Location**: File and line number when possible
- **Metadata**: Include CWE, CVSS, OWASP references when available

Example:

```typescript
{
  title: "SQL Injection via User Input",
  description: "User-controlled input is concatenated into SQL query without sanitization",
  severity: "critical",
  location: { file: "app.js", line: 42 },
  metadata: {
    cwe: ["CWE-89"],
    owasp: ["A03:2021"],
    cvss: 9.8
  }
}
```

## Documentation

- Update `README.md` if you add user-facing features
- Update tool's `CLAUDE.md` if you change internal behavior
- Add JSDoc comments to exported functions

## Commit Messages

Use clear, descriptive commit messages:

✅ Good:
- `Add progress reporting to scan_code tool`
- `Fix check_secrets failing on empty repos`
- `Update README installation instructions for Windows`

❌ Bad:
- `fix bug`
- `updates`
- `wip`

## Pull Request Checklist

Before submitting:

- [ ] Code builds without errors (`npm run build`)
- [ ] Server starts without crashes (`node dist/index.js`)
- [ ] Tested with a real project in Cursor
- [ ] Updated documentation if needed
- [ ] Commit messages are clear
- [ ] No sensitive data (API keys, secrets) in code

## Questions or Issues?

- **Bug reports**: Open a GitHub Issue with steps to reproduce
- **Feature requests**: Open a GitHub Issue explaining the use case
- **Questions**: Open a Discussion or reach out via Issues

## Code of Conduct

- Be respectful and constructive
- Welcome newcomers
- Focus on what's best for the project
- Give credit where it's due

Thank you for contributing to making development more secure! 🛡️
