#!/bin/bash

# SecureDev MCP Installation Script
# For Mac and Linux

set -e  # Exit on error

echo "🛡️  SecureDev MCP Installation Script"
echo "===================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Node.js
echo "Checking prerequisites..."
if ! command -v node &> /dev/null; then
    echo -e "${RED}✗ Node.js not found${NC}"
    echo "Please install Node.js 20+ from https://nodejs.org"
    exit 1
fi

NODE_VERSION=$(node --version | cut -d 'v' -f 2 | cut -d '.' -f 1)
if [ "$NODE_VERSION" -lt 20 ]; then
    echo -e "${RED}✗ Node.js version too old (found v$NODE_VERSION, need v20+)${NC}"
    echo "Please upgrade Node.js from https://nodejs.org"
    exit 1
fi

echo -e "${GREEN}✓ Node.js $(node --version)${NC}"

# Check npm
if ! command -v npm &> /dev/null; then
    echo -e "${RED}✗ npm not found${NC}"
    exit 1
fi
echo -e "${GREEN}✓ npm $(npm --version)${NC}"

# Install Node dependencies
echo ""
echo "Installing Node dependencies..."
npm install
echo -e "${GREEN}✓ Dependencies installed${NC}"

# Build project
echo ""
echo "Building project..."
npm run build
echo -e "${GREEN}✓ Project built${NC}"

# Check security tools
echo ""
echo "Checking security scanners..."

HAS_GITLEAKS=false
HAS_SEMGREP=false
HAS_OSV=false

if command -v gitleaks &> /dev/null; then
    echo -e "${GREEN}✓ gitleaks installed${NC}"
    HAS_GITLEAKS=true
else
    echo -e "${YELLOW}⚠ gitleaks not found${NC}"
fi

if command -v semgrep &> /dev/null; then
    echo -e "${GREEN}✓ semgrep installed${NC}"
    HAS_SEMGREP=true
else
    echo -e "${YELLOW}⚠ semgrep not found${NC}"
fi

if command -v osv-scanner &> /dev/null; then
    echo -e "${GREEN}✓ osv-scanner installed${NC}"
    HAS_OSV=true
else
    echo -e "${YELLOW}⚠ osv-scanner not found${NC}"
fi

# Offer to install missing tools
if [ "$HAS_GITLEAKS" = false ] || [ "$HAS_SEMGREP" = false ] || [ "$HAS_OSV" = false ]; then
    echo ""
    echo "Some security scanners are missing. Would you like to install them? (y/n)"
    read -r INSTALL_SCANNERS

    if [ "$INSTALL_SCANNERS" = "y" ] || [ "$INSTALL_SCANNERS" = "Y" ]; then
        # Detect package manager
        if command -v brew &> /dev/null; then
            echo "Installing with Homebrew..."
            [ "$HAS_GITLEAKS" = false ] && brew install gitleaks
            [ "$HAS_SEMGREP" = false ] && brew install semgrep
            [ "$HAS_OSV" = false ] && brew install osv-scanner
            echo -e "${GREEN}✓ Security scanners installed${NC}"
        else
            echo ""
            echo "Homebrew not found. Please install manually:"
            [ "$HAS_GITLEAKS" = false ] && echo "  - gitleaks: https://github.com/gitleaks/gitleaks#installing"
            [ "$HAS_SEMGREP" = false ] && echo "  - semgrep: pip install semgrep"
            [ "$HAS_OSV" = false ] && echo "  - osv-scanner: brew install osv-scanner"
        fi
    fi
fi

# Setup .env file
echo ""
if [ ! -f .env ]; then
    echo "Creating .env file..."
    cp .env.example .env
    echo -e "${GREEN}✓ .env file created${NC}"
    echo ""
    echo -e "${YELLOW}⚠ Please edit .env and add your ANTHROPIC_API_KEY${NC}"
    echo "   Get a key from: https://console.anthropic.com/"
else
    echo -e "${GREEN}✓ .env file already exists${NC}"
fi

# Get absolute path
INSTALL_PATH=$(pwd)

echo ""
echo "===================================="
echo -e "${GREEN}✅ Installation complete!${NC}"
echo "===================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Add SecureDev to your AI IDE:"
echo ""
echo "   For Cursor, add to ~/.cursor/mcp.json:"
echo ""
echo "   {"
echo "     \"mcpServers\": {"
echo "       \"securedev\": {"
echo "         \"command\": \"node\","
echo "         \"args\": [\"$INSTALL_PATH/dist/index.js\"],"
echo "         \"env\": {"
echo "           \"ANTHROPIC_API_KEY\": \"your-key-here\""
echo "         }"
echo "       }"
echo "     }"
echo "   }"
echo ""
echo "2. Restart your IDE"
echo ""
echo "3. Try it out:"
echo "   Ask your AI: 'Check my code for security vulnerabilities'"
echo ""
echo "Need help? See README.md or visit https://github.com/your-repo/securedev-mcp"
echo ""
