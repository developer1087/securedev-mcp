# SecureDev MCP

**Security-first development tools for Cursor/Claude Code**

An MCP (Model Context Protocol) server that provides 7 security tools for developers, designed to "think in security, speak in development."

## Features

- 🔍 **scan_code** ✅ - SAST-light using Semgrep + Gitleaks (working tree)
- 📦 **analyze_dependencies** ✅ - SCA using osv-scanner + npm audit
- 🏗️ **analyze_architecture** ✅ - Architecture threat analysis with Claude API + deterministic rules
- 🎯 **threat_model** ✅ - Proactive STRIDE threat modeling before implementation
- 🔑 **check_secrets** ✅ - Git history secret scanning with Gitleaks
- 📋 **generate_sbom** ✅ - SBOM generation (CycloneDX/SPDX) with license analysis
- 💡 **get_guidance** ✅ - Contextual security guidance with Claude API

**All 7 tools fully implemented** ✅

## Installation

### Prerequisites

1. **Node.js 20+**
   ```bash
   node --version  # should be >= 20.0.0
   ```

2. **External Tools** (required for specific features):
   ```bash
   # Gitleaks (for check_secrets, scan_code)
   brew install gitleaks  # macOS
   # or
   scoop install gitleaks  # Windows

   # Semgrep (for scan_code) - Phase 2
   brew install semgrep
   # or
   pip install semgrep

   # osv-scanner (for analyze_dependencies) - Phase 2
   brew install osv-scanner
   ```

3. **Claude API Key** (for analyze_architecture, threat_model, get_guidance):
   - Get API key from: https://console.anthropic.com/
   - Add to `.env`: `ANTHROPIC_API_KEY=sk-ant-...`

### Setup

```bash
# Clone/navigate to project
cd securedev-mcp

# Install dependencies
npm install

# Build
npm run build

# Copy environment template
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

## Usage with Cursor

Add to your `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "securedev": {
      "command": "node",
      "args": ["/path/to/securedev-mcp/dist/index.js"],
      "env": {
        "ANTHROPIC_API_KEY": "your-key-here"
      }
    }
  }
}
```

Then restart Cursor and use the tools:

```
@securedev check_secrets with scope=history
@securedev analyze_architecture
@securedev threat_model for user login feature
```

## Project Structure

```
securedev-mcp/
├── CLAUDE.md                    # Main context file
├── src/
│   ├── index.ts                 # MCP server entry point
│   ├── session/                 # Session management
│   │   ├── context.ts           # In-memory session store
│   │   └── score.ts             # Security score calculation
│   ├── shared/                  # Shared utilities
│   │   ├── types.ts             # TypeScript interfaces
│   │   ├── interrupt.ts         # Interrupt level logic
│   │   ├── claude-client.ts     # Claude API wrapper
│   │   ├── formatter.ts         # Output formatting
│   │   └── delta.ts             # Threat model delta reports
│   └── tools/                   # 7 security tools
│       ├── check-secrets/       # ✅ Fully implemented
│       ├── scan-code/           # ✅ Fully implemented
│       ├── analyze-dependencies/# ✅ Fully implemented
│       ├── analyze-architecture/# ✅ Fully implemented
│       ├── threat-model/        # ✅ Fully implemented
│       ├── generate-sbom/       # ✅ Fully implemented
│       └── get-guidance/        # ✅ Fully implemented
└── extension/                   # VS Code extension (future)
```

Each directory has a `CLAUDE.md` file with detailed context and implementation notes.

## Development

```bash
# Watch mode (auto-rebuild on changes)
npm run watch

# Run directly with ts-node
npm run dev
```

## Security Score Formula

```
score = 100
  - (critical_findings × 15)
  - (high_findings × 7)
  - (medium_findings × 3)
  - (low_findings × 1)
  - (delta_misses × 10)
  - (live_secrets × 20)
  + (tools_run × 2)
min(score, 0)
```

## Interrupt Levels

- **🛑 hard_stop**: Critical + actively exploited → requires user action before continuing
- **⚠️ action_required**: High severity → recommended to address before deploy
- **ℹ️ monitor**: Medium/low → FYI

## Phase 1 vs Phase 2

**Phase 1 (Complete):**
- ✅ Full scaffolding
- ✅ All 7 security tools fully implemented:
  - check_secrets - Git history secret scanning
  - scan_code - SAST with Semgrep + Gitleaks
  - analyze_dependencies - SCA with osv-scanner + npm audit
  - generate_sbom - SBOM generation with license analysis
  - analyze_architecture - Architecture threat analysis
  - threat_model - STRIDE threat modeling
  - get_guidance - Contextual security guidance
- ✅ In-memory session management
- ✅ Security score calculation
- ✅ Interrupt level system

**Phase 2 (Future):**
- Persistent session storage
- VS Code extension with dashboard
- Additional integrations (Socket.dev, etc.)
- AI/LLM security layer
- Web companion app

## Contributing

See `docs/CLAUDE.md` for architectural decisions and references.

## License

MIT
