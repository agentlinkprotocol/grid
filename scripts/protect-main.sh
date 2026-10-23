#!/usr/bin/env bash
# Protect `main` on one or more repositories: pull requests only, the `tests` check of the `ci`
# workflow must pass, no force push, no deletion. Needs `gh auth login` with admin rights.
#
#   scripts/protect-main.sh agentlinkprotocol/grid agentlinkprotocol/typescript-sdk ...
set -euo pipefail
for REPO in "$@"; do
  echo "== $REPO"
  EXISTING=$(gh api "repos/$REPO/rulesets" --jq '.[] | select(.name=="protect-main") | .id' || true)
  BODY=$(cat <<'JSON'
{
  "name": "protect-main",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/heads/main"], "exclude": [] } },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "pull_request", "parameters": { "required_approving_review_count": 0, "dismiss_stale_reviews_on_push": true, "require_code_owner_review": false, "require_last_push_approval": false, "required_review_thread_resolution": false } },
    { "type": "required_status_checks", "parameters": { "strict_required_status_checks_policy": true, "required_status_checks": [ { "context": "tests" } ] } }
  ]
}
JSON
)
  if [ -n "$EXISTING" ]; then
    echo "$BODY" | gh api -X PUT "repos/$REPO/rulesets/$EXISTING" --input - >/dev/null && echo "updated ruleset $EXISTING"
  else
    echo "$BODY" | gh api -X POST "repos/$REPO/rulesets" --input - >/dev/null && echo "created ruleset"
  fi
done
echo "done: merging into main now requires a pull request with the 'tests' check green."
