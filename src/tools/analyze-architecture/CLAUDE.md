# analyze_architecture Tool

## Flow
1. detector.ts — סורק קבצי config, מחלץ components
2. Confirmation Step — מחזיר לMCP client לאישור
3. llm-analyzer.ts — Claude API עם architecture context
4. rules.ts — בדיקות דטרמיניסטיות
5. מיזוג תוצאות → findings + threatMap

## Detector — מה לחפש
- docker-compose.yml: services, ports, networks, environment
- .env.example: מה חשוף, אילו שירותים
- nginx.conf: upstream, proxy_pass, ssl
- package.json: dependencies → framework detection
- route files: endpoints, middleware pattern

## LLM System Prompt Pattern
```
You are a security architect analyzing application architecture.
Detected components: {detected_components}
Task: Identify architectural security threats using STRIDE.
Only report threats that are clearly present — do not speculate.
For each threat: title (professional security term), description (technical),
strideCategory, severity, affectedComponents, cwe, nistControl, mitigations.
Language: match user language (Hebrew/English).
```

## Rule Engine (rules.ts) — דטרמיניסטי
- No network isolation: services share default Docker network → hard_stop
- Redis no auth: REDIS_PASSWORD not set → action_required
- Shared env: same .env for dev+prod → action_required
- Admin routes no separation: /admin/* same app instance → action_required
- HTTP internal traffic: service URLs use http:// → monitor
