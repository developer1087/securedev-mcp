# Shared Utilities

## types.ts
כל ה-TypeScript interfaces משותפים:
- Finding, DepFinding, ArchFinding, SecretFinding, ThreatModelFinding
- SessionContext, Component, Feature, Package, LicenseIssue
- InterruptLevel, Severity
- GuidanceResponse

## interrupt.ts
לוגיקה לחישוב InterruptLevel:
```typescript
function calculateInterruptLevel(
  severity: Severity,
  metadata: { cvss?: number; hasActivePoc?: boolean; isKEV?: boolean }
): InterruptLevel
```

## formatter.ts
המרת findings ל-human-readable format:
- formatFinding(finding): markdown string
- formatSeverityBadge(severity): emoji + color
- formatLocation(location): file:line או component name
- maskSecret(secret): ••••last4chars

## claude-client.ts
Wrapper על Anthropic SDK:
- retry logic (3 attempts, exponential backoff)
- error handling + user-friendly messages
- rate limit handling
- model: claude-sonnet-4-20250514

## delta.ts
Delta report logic:
- compareThreatModelToFindings(threatModel, scanFindings): DeltaReport
- DeltaReport: { misses: [], ok: [], new: [] }
