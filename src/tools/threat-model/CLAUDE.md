# threat_model Tool

## Flow
1. קבל תיאור חופשי מהמפתח
2. החזר clarifying questions (4 שאלות קבועות + dynamic אם צריך)
3. קבל תשובות
4. Claude API → STRIDE analysis
5. שמור baseline ל-SessionContext.threatModel

## 4 Clarifying Questions (קבועות)
1. מי יכול לגשת לפיצ'ר? (authenticated / public / admin)
2. האם הנתונים גלויים לאחרים? (public / friends / private)
3. איך הנתונים נשמרים? (DB / file storage / cloud / memory)
4. האם יש עיבוד של הנתונים? (processing type)

## STRIDE Filter
לא כל פיצ'ר רלוונטי לכל 6 קטגוריות.
Claude מחליט אילו קטגוריות רלוונטיות ומסביר בשורה אחת למה S/R לא רלוונטי אם כך.

## LLM System Prompt Pattern
```
You are a security architect performing threat modeling.
Feature: {feature_description}
Context: {clarifications}
Existing architecture: {session_context.architecture}
Task: STRIDE threat model. Only include applicable STRIDE categories.
For each threat: strideCategory, severity, title, description, mitigations (as actions), cwe, cvssVector.
Be specific — reference actual implementation details where possible.
Language: match user language (Hebrew/English).
```

## Baseline
baseline = threatModel.threats
משמש ל-delta report: השוואה לממצאים בפועל מ-scan_code/analyze_dependencies.
