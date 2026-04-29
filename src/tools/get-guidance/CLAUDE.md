# get_guidance Tool

## 3 Modes
1. answer: שאלה ישירה מהמפתח
2. push: אחרי כלי אחר — יזום הצעת guidance רלוונטית
3. escalate: שאלה מחוץ לסקופ — הסבר למה ומה כן אפשר

## Context Injection
תמיד inject לפרומפט:
- project.stack
- architecture.components (אם קיים)
- scanFindings summary (אם קיים)
- threatModel baseline (אם קיים)

## Push Triggers
אחרי scan_code: אם >2 findings מאותה קטגוריה → הצע הסבר על הדפוס
אחרי threat_model: אחרי שמירת baseline → הצע implementation checklist
אחרי analyze_dependencies: אם hard_stop dep → הצע migration path

## Escalation Triggers (מחזיר responseType: 'escalate')
- incident_response: מילות מפתח: "נפרץ", "breach", "compromised", "forensics", "IR"
- architectural_decision: "האם לעבור ל", "מיקרוסרביס", "monolith", "rewrite"
- legal_advice: "האם מותר", "רישיון", "GDPR compliance", "legal"
- insufficient_context: Claude מחזיר confidence < 0.7

## LLM System Prompt Pattern
```
You are a security advisor for developers.
Context: {session_context}
Question: {user_question}
Task: Provide actionable security guidance.
Tone: Technical but accessible. Developer audience, not security auditor.
For code examples: use the project's actual tech stack.
References: always cite CWE, OWASP, or NIST where relevant.
Language: match user language (Hebrew/English).
If the question is outside your scope, explain why and suggest alternatives.
```

## Response Structure
```typescript
{
  responseType: 'answer' | 'push_suggestion' | 'escalate';
  content: string;
  codeExample?: string;
  references?: string[];      // ['CWE-89', 'OWASP A03:2021']
  followUpSuggestions?: string[];
  escalationReason?: string;
  escalationAlternative?: string; // מה כן אפשר לעשות
}
```
