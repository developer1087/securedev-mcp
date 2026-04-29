# Webview Panel

## טכנולוגיה
VS Code Webview API — HTML/CSS/JS vanilla (אין framework).
הפאנל נפתח מ-extension/extension.ts.
תקשורת: panel.webview.postMessage() / window.addEventListener('message').

## ארבעה טאבים
1. Overview: security score (SVG ring), tool status dots, top 3 findings
2. Findings: כל הממצאים ממוינים לפי severity, filterable
3. Delta: threat_model baseline vs scan results (Miss / OK / New)
4. Tools: re-run כלים, session context display

## Score Ring
SVG circle עם stroke-dasharray דינמי לפי score.
צבע: score > 80 → green, 60-80 → amber, < 60 → red.

## Real-time Updates
כל פעם שכלי מסיים ריצה → MCP server שולח event → panel מתעדכן.
Status dots: gray (idle) / blue+pulse (running) / green (ok) / amber (warnings) / red (critical).

## Language Support
כל טקסט בממשק ב-i18n object:
{ he: { findingsTab: "ממצאים", ... }, en: { findingsTab: "Findings", ... } }
שפה נקבעת לפי VS Code locale או user setting.

## Design System
CSS variables בלבד — אין hardcoded colors.
תאימות dark mode מלאה.
