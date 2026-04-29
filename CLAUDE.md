# SecureDev MCP

## מה זה
MCP server שחושף 7 כלי אבטחה למפתחים בתוך Cursor/Claude Code.
עיקרון: הכלי חושב בסייבר, מדבר בפיתוח.

## Tech Stack
- TypeScript 5 + Node.js 20
- MCP SDK: @modelcontextprotocol/sdk
- Scanning: Semgrep (OSS), Gitleaks, osv-scanner — כולם חינמיים
- LLM: Claude API (claude-sonnet-4-20250514) לניתוח ארכיטקטורה ו-threat modeling
- IDE Panel: VS Code Extension + Webview
- Session: In-memory (Node.js Map) — אין persistence בשלב זה

## 7 הכלים
1. scan_code — Semgrep + Gitleaks (working tree)
2. analyze_dependencies — osv-scanner + npm audit
3. analyze_architecture — detector + Claude API + rule engine
4. threat_model — STRIDE via Claude API
5. check_secrets — Gitleaks (full git history)
6. generate_sbom — CycloneDX 1.5 JSON default
7. get_guidance — Claude API + session context injection

## Session Context
כל כלי קורא ו/או כותב ל-SessionContext (in-memory).
SessionContext חי ב-src/session/context.ts.
get_guidance תמיד מקבל את ה-context המלא.

## UX Principles
- כותרת finding = שם פגיעות מקצועי (SQL Injection, לא "תוקף יכול לפגוע בך")
- שורה 2 = הסבר טכני קצר
- CWE/CVSS/OWASP = footer, לא headline
- "why this matters" = opt-in
- Interrupt levels: hard_stop / action_required / monitor
- שפה: תמיכה בעברית ואנגלית

## Interrupt Levels
- hard_stop: critical + actively exploited — חייב בחירת פעולה לפני המשך
- action_required: high — מומלץ לטפל לפני deploy
- monitor: medium/low — FYI

## External Dependencies
כלים חיצוניים (חובה להתקין):
- semgrep: brew install semgrep / pip install semgrep
- gitleaks: brew install gitleaks / scoop install gitleaks
- osv-scanner: brew install osv-scanner / go install ...

## Environment Variables
ANTHROPIC_API_KEY — חובה לכלים: analyze_architecture, threat_model, get_guidance

## מה לא לעשות
- אין persistence של session (Phase 2)
- אין Socket.dev API (Phase 2)
- אין AI/LLM security layer (Phase 2)
- אין web companion app (Phase 2)
