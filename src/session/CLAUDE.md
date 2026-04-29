# Session Management

## SessionContext Structure
```typescript
interface SessionContext {
  project: {
    name: string;
    stack: string[];
    entrypoints: string[];
    isPublicFacing: boolean;
    hasPayments: boolean;
  };
  threatModel?: {
    features: Feature[];
    threats: ThreatModelFinding[];
    savedAt: Date;
  };
  scanFindings?: {
    code: Finding[];
    deps: DepFinding[];
    scannedAt: Date;
  };
  architecture?: {
    components: Component[];
    threats: ArchFinding[];
    analyzedAt: Date;
  };
  secrets?: {
    live: SecretFinding[];
    scannedAt: Date;
  };
  sbom?: {
    packages: Package[];
    licenseIssues: LicenseIssue[];
    generatedAt: Date;
  };
}
```

## Score Formula
```
score = 100
  - (critical_findings * 15)
  - (high_findings * 7)
  - (medium_findings * 3)
  - (low_findings * 1)
  - (delta_misses * 10)
  - (live_secrets * 20)
  + (tools_run * 2)
min(score, 0)
```

## Delta Report Logic
השוואה בין threatModel.threats לבין scanFindings:
- Miss: איום שהוגדר ב-threat_model, לא נמצאה מיטיגציה בסריקות
- OK: איום שהוגדר, נמצאה מיטיגציה
- New: ממצא שלא היה ב-threat_model המקורי
