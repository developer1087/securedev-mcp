# generate_sbom Tool

## פורמטים
- ברירת מחדל: CycloneDX 1.5 JSON
- נוספים: CycloneDX 1.5 XML, SPDX 2.3 JSON

## Library
השתמש ב-@cyclonedx/cyclonedx-library לייצור CycloneDX.
השתמש ב-spdx-tools לייצור SPDX.

## License Flags
GPL-3.0, GPL-2.0: copyleft — flag ל-review, הפנה ליועץ משפטי
LGPL-2.1, LGPL-3.0: flag ל-review
AGPL-3.0: flag ל-review (חמור יותר מ-GPL בהקשר SaaS)
MIT, ISC, Apache-2.0, BSD-*: ok

## EOL Detection
בדוק אל מול: https://endoflife.date/api (חינמי)
Unmaintained: אין commits ב-2 שנים אחרונות (GitHub API)

## Summary Output
תמיד החזר summary ויזואלי בנוסף לקובץ:
- totalPackages, direct, transitive
- licenseBreakdown: [{license, count, status}]
- licenseIssues: [{license, packages[], reason}]
- eolPackages: [{package, eolDate, currentVersion}]
- unmaintainedPackages: [{package, lastCommit}]
