# scan_code Tool

## מה זה עושה
SAST-light — סריקת קוד סטטית על working tree.
Engines: Semgrep (rules: auto + p/security-audit) + Gitleaks (working tree only).

## Input Schema
```typescript
{
  files: string[];
  context: {
    projectType: 'web-app' | 'api' | 'cli' | 'library';
    hasPayments: boolean;
  };
}
```

## Semgrep
- Command: `semgrep --config=auto --config=p/security-audit --json <files>`
- Parse output: results[].check_id, path, start.line, extra.message, extra.severity
- Map severity: ERROR→critical, WARNING→high, INFO→medium

## Gitleaks (working tree)
- Command: `gitleaks detect --source=. --report-format=json --report-path=/tmp/gl.json`
- Parse: RuleID, File, StartLine, Secret (mask all but last 4 chars)
- תמיד hard_stop אם נמצא secret חי

## Output → SessionContext
כותב ל: context.scanFindings.code
