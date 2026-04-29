# check_secrets Tool

## מה זה עושה
סריקת secrets ב-git — working tree, full history, או branch ספציפי.
חשוב: secret שנמחק מה-working tree עדיין קיים ב-history.

## Gitleaks Commands
```bash
# working tree
gitleaks detect --source=. --report-format=json --report-path=/tmp/gl-work.json

# full history
gitleaks detect --source=. --log-opts="--all" --report-format=json --report-path=/tmp/gl-hist.json

# specific branch
gitleaks detect --source=. --log-opts="<branch>" --report-format=json --report-path=/tmp/gl-branch.json
```

## State Detection
live: secret appears in current HEAD (working tree scan finds it)
history: secret in git log but not in HEAD
branch_only: secret in branch commits but branch never merged to main

## Masking
מציג רק 4 תווים אחרונים: sk_live_••••3f9a
הערך המלא לא מוחזר ב-output לעולם.

## Rotation Steps (generic — לא navigation ספציפי)
תמיד 4 שלבים לוגיים:
1. Generate new credential in target service
2. Update application config with new value
3. Verify application works with new credential
4. Revoke old credential in target service

אם repo ציבורי — בדוק logs לשימוש לא מורשה בתקופת החשיפה
