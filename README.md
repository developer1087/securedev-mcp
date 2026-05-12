# SecureDev MCP

**Your AI coding assistant just got security superpowers** 🛡️

SecureDev MCP adds 7 security tools to your AI IDE (like Cursor), so your AI can automatically check your code for vulnerabilities, leaked secrets, and security issues - just by asking it in plain English.

## Why Use This?

Instead of manually running security scanners or remembering complex commands, just ask your AI:

- *"Check if I accidentally committed any passwords or API keys"*
- *"Scan my code for security vulnerabilities"*
- *"Are any of my dependencies vulnerable?"*
- *"Generate a security report for this project"*

Your AI assistant will use these professional security tools automatically and explain the results in plain English.

## The 7 Security Tools

| Tool | What It Does | Example Use |
|------|-------------|-------------|
| 🔍 **scan_code** | Finds security bugs in your code (SQL injection, XSS, etc.) | "Scan my code for security issues" |
| 📦 **analyze_dependencies** | Checks if any packages you're using have known vulnerabilities | "Check if my dependencies are safe" |
| 🏗️ **analyze_architecture** | Reviews your app's architecture for security weaknesses | "Analyze my docker-compose setup for security issues" |
| 🎯 **threat_model** | Thinks through potential attacks on a new feature | "What security threats should I consider for my login page?" |
| 🔑 **check_secrets** | Scans your entire git history for leaked passwords/keys | "Check if I ever committed secrets" |
| 📋 **generate_sbom** | Creates a list of all packages (required for compliance) | "Generate an SBOM for this project" |
| 💡 **get_guidance** | Answers security questions about your code | "How do I securely store passwords in Node.js?" |

## Quick Start (5 minutes)

### Step 1: Check Prerequisites

You need **Node.js 20+** installed. Check by opening Terminal/Command Prompt:

```bash
node --version
```

If it shows `v20.0.0` or higher, you're good! If not, download Node.js from [nodejs.org](https://nodejs.org).

### Step 2: Install Security Scanners

These are free, open-source tools that SecureDev uses:

**On Mac (using Homebrew):**
```bash
brew install gitleaks semgrep osv-scanner
```

**On Windows (using Scoop):**
```bash
scoop install gitleaks
pip install semgrep
go install github.com/google/osv-scanner/cmd/osv-scanner@latest
```

**On Linux:**
```bash
# Gitleaks
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/

# Semgrep
pip install semgrep

# OSV-Scanner
go install github.com/google/osv-scanner/cmd/osv-scanner@latest
```

### Step 3: Get a Claude API Key

Some tools (architecture analysis, threat modeling, security advice) use Claude AI:

1. Go to [console.anthropic.com](https://console.anthropic.com/)
2. Sign up (free trial available)
3. Create an API key
4. Copy it (looks like `sk-ant-api03-...`)

**Don't have an API key yet?** That's okay! 4 out of 7 tools work without it (scan_code, analyze_dependencies, check_secrets, generate_sbom).

### Step 4: Install SecureDev MCP

```bash
# Download this repository
cd ~/Desktop  # or wherever you want to install
git clone https://github.com/your-username/securedev-mcp.git
cd securedev-mcp

# Install
npm install
npm run build

# Add your API key (optional but recommended)
cp .env.example .env
# Edit .env file and paste your Claude API key
```

### Step 5: Connect to Cursor (or your AI IDE)

**For Cursor:**

1. Open Cursor
2. Press `Cmd+Shift+P` (Mac) or `Ctrl+Shift+P` (Windows/Linux)
3. Type "MCP Settings" and press Enter
4. This opens a file called `mcp.json`
5. Add this code (replace `/path/to/securedev-mcp` with the actual path):

```json
{
  "mcpServers": {
    "securedev": {
      "command": "node",
      "args": ["/Users/yourname/Desktop/securedev-mcp/dist/index.js"],
      "env": {
        "ANTHROPIC_API_KEY": "sk-ant-api03-paste-your-key-here"
      }
    }
  }
}
```

6. Save the file
7. Restart Cursor

**For Claude Code (CLI):**

Add to `~/.config/claude-code/config.json`:

```json
{
  "mcpServers": {
    "securedev": {
      "command": "node",
      "args": ["/Users/yourname/Desktop/securedev-mcp/dist/index.js"],
      "env": {
        "ANTHROPIC_API_KEY": "your-key-here"
      }
    }
  }
}
```

### Step 6: Try It Out!

In Cursor's chat, type:

```
Check my code for security vulnerabilities
```

or

```
Scan my git history for leaked secrets
```

The AI will automatically use the security tools and explain the results!

## Common Questions

**Q: Do I need all the tools installed?**
A: No! The tool will tell you which scanner is missing and still run what it can. But for best results, install all three (gitleaks, semgrep, osv-scanner).

**Q: Is my code sent anywhere?**
A: Code scanning happens locally on your computer. Only architecture analysis and guidance use Claude API (and only send necessary context, not your entire codebase).

**Q: How much does this cost?**
A: SecureDev MCP is free and open-source. The external scanners are also free. Claude API has a free trial, then costs about $0.003 per 1000 words analyzed.

**Q: Can I use this in CI/CD?**
A: Yes! While it's designed for interactive use with AI, you can also call the tools directly in automation. Documentation coming soon.

**Q: What if I get an error?**
A: See the **Troubleshooting** section below!

## Troubleshooting

### "command not found: node"
- **Solution:** Install Node.js from [nodejs.org](https://nodejs.org)

### "SecureDev MCP server not responding"
- **Solution:** Make sure you ran `npm run build` and restarted Cursor
- Check that the path in `mcp.json` is correct (use full absolute path)

### "Gitleaks/Semgrep not installed"
- **Solution:** Run the install commands from Step 2 above
- Check if installed by running: `gitleaks version` or `semgrep --version`

### "ANTHROPIC_API_KEY not set"
- **Solution:** Either add it to the `.env` file, or add it to `mcp.json` under `"env"`
- Only needed for 3 tools (architecture analysis, threat modeling, guidance)

### "No progress bars showing"
- **Solution:** Progress bars are shown by your AI IDE (Cursor). Make sure you're on the latest version.
- The tools still work even if progress isn't visible!

## What's Next?

- **Phase 1 (Current):** All 7 tools working with progress tracking ✅
- **Phase 2 (Coming Soon):**
  - Visual dashboard showing security score
  - Integration with more security tools
  - Persistent scan history
  - Team collaboration features

## Advanced: Project Structure

For developers who want to contribute or understand the internals:

```
securedev-mcp/
├── src/
│   ├── index.ts                 # MCP server (connects to your IDE)
│   ├── tools/                   # The 7 security tools
│   │   ├── scan-code/           # Code vulnerability scanner
│   │   ├── analyze-dependencies/# Dependency vulnerability checker
│   │   ├── check-secrets/       # Secret leak detector
│   │   ├── analyze-architecture/# Architecture threat analyzer
│   │   ├── threat-model/        # STRIDE threat modeler
│   │   ├── generate-sbom/       # Software bill of materials generator
│   │   └── get-guidance/        # Security Q&A assistant
│   └── shared/
│       ├── progress.ts          # Progress bar support
│       ├── claude-client.ts     # Claude API integration
│       └── types.ts             # TypeScript definitions
└── dist/                        # Compiled code (generated by npm run build)
```

## Contributing

Found a bug? Have an idea? Contributions are welcome!

1. Fork this repo
2. Create a branch: `git checkout -b my-feature`
3. Make your changes
4. Test: `npm run build && node dist/index.js`
5. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## Security

**Found a security vulnerability in SecureDev itself?**
Please email security@example.com instead of creating a public issue.

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

Made with ❤️ by developers who care about security

⭐ Star this repo if you find it useful!
