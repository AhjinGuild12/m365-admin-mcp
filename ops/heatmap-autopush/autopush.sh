#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
LOCK="/tmp/m365-admin-mcp-autopush.lock"
git remote get-url origin >/dev/null 2>&1 || { echo "no origin"; exit 0; }
git diff --quiet && git diff --cached --quiet && [ -z "$(git ls-files --others --exclude-standard)" ] && exit 0
[ -f "$LOCK" ] && [ $(( $(date +%s) - $(stat -f %m "$LOCK") )) -lt 300 ] && exit 0
echo $$ > "$LOCK"; trap 'rm -f "$LOCK"' EXIT
git add -A
git diff --cached --quiet && exit 0
git diff --cached --name-only | grep -E '(^|/)\.env(\.|$)|\.pem$|\.key$' && { echo refuse secrets; exit 1; }
git commit -m "chore: autosave $(date '+%Y-%m-%d %H:%M %Z')"
git push -u origin HEAD
