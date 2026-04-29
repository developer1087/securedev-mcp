# Tools — General Patterns

## כל tool חייב:
1. להיות רשום ב-src/index.ts דרך MCP SDK
2. לקרוא מ-SessionContext בתחילת הריצה
3. לכתוב את הממצאים ל-SessionContext בסיום
4. להחזיר findings ממוינים: critical → high → medium → low
5. לכלול בכל finding:
   - title: מקצועי, טכני
   - description: הסבר טכני קצר
   - severity: critical / high / medium / low
   - interruptLevel: hard_stop / action_required / monitor
   - location: {file, line} או {component}
   - metadata: {cwe?, cvss?, owasp?, references?}

## Title Guidelines
כותרות findings חייבות להיות מקצועיות וטכניות:
✓ "SQL Injection via User Input"
✓ "Hardcoded AWS Credentials"
✓ "Plaintext Password Storage"
✓ "Missing Network Segmentation"
✗ "המשתמש יכול למחוק את הדאטהבייס"
✗ "סיסמאות לא מוצפנות"

## InterruptLevel Logic (src/shared/interrupt.ts)
hard_stop: severity === 'critical' && (hasActivePoc || cvss >= 9.5)
action_required: severity === 'high' || (severity === 'critical' && !hasActivePoc)
monitor: severity === 'medium' || severity === 'low'

## LLM Tools (analyze_architecture, threat_model, get_guidance)
משתמשים ב-src/shared/claude-client.ts
model: claude-sonnet-4-20250514
תמיד inject את ה-SessionContext הרלוונטי ל-system prompt
