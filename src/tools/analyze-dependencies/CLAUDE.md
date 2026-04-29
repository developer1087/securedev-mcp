# analyze_dependencies Tool

## מה זה עושה
SCA — סריקת dependencies כולל transitive.
Engines: osv-scanner + npm audit (Node.js) / pip-audit (Python).

## osv-scanner
- Command: `osv-scanner --format=json <lockfile>`
- Parse: results[].packages[].vulnerabilities[]
- Map: vuln.id (CVE/GHSA), aliases, severity, affected[].ranges

## npm audit
- Command: `npm audit --json`
- Parse: vulnerabilities[].severity, via[], range
- via[] = dependency chain → depChain

## Depth Detection
depth 1: package in direct dependencies (package.json dependencies/devDependencies)
depth 2+: package appears only in lockfile, not in package.json

## Hard Stop Condition
cvss >= 9.0 AND (hasActivePoc === true OR isKEV === true)
KEV = CISA Known Exploited Vulnerabilities list
