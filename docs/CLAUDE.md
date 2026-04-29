# Documentation

## References
- MCP SDK: https://github.com/modelcontextprotocol/sdk
- Semgrep: https://semgrep.dev/docs/
- Gitleaks: https://github.com/gitleaks/gitleaks
- osv-scanner: https://google.github.io/osv-scanner/
- CycloneDX: https://cyclonedx.org/
- STRIDE: https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats

## Decisions Log
- 2026-04-28: Project initialized, in-memory session only (Phase 1)
- Model choice: claude-sonnet-4-20250514 for balance of speed/quality
- No persistence in Phase 1 — simplicity first
- Semgrep over commercial SAST — cost-effective, open source
- CycloneDX as default SBOM format — industry standard
