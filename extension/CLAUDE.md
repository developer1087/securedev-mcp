# VS Code Extension

## Entry Point
extension/extension.ts — נרשם כ-VS Code extension.
מפעיל את ה-MCP server כ-child process.
פותח Webview Panel בלחיצה על Activity Bar icon.

## Commands
- securedev.openPanel: פתיחת dashboard
- securedev.scanCode: הרץ scan_code
- securedev.checkSecrets: הרץ check_secrets
- securedev.analyzeDeps: הרץ analyze_dependencies

## MCP Configuration (לCursor)
המשתמש צריך להוסיף ל-.cursor/mcp.json:
```json
{
  "mcpServers": {
    "securedev": {
      "command": "node",
      "args": ["<path>/securedev-mcp/dist/index.js"],
      "env": {
        "ANTHROPIC_API_KEY": "<key>"
      }
    }
  }
}
```
