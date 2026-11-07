#!/usr/bin/env bash
# One-time GitHub setup for the automation in docs/AUTOMATION.md. Safe to re-run.
# Needs the gh CLI logged in as a repository admin. See that document for the
# steps that can't be scripted (npm trusted publishing, the Claude GitHub App).
set -euo pipefail

REPO="${1:-rajssinde/rs-native-kit-security}"
RELEASE_ENV=npm-publish
FIRST_TAG=v0.1.0
FIRST_TAG_COMMIT=9fa9cd17cd225a6b6022db0b7bd7a5a42a20a5de # npm gitHead of 0.1.0

echo "Labels"
while IFS='|' read -r name color description; do
  gh label create "$name" --repo "$REPO" --color "$color" --description "$description" --force
done <<'LABELS'
android|3DDC84|Android
ios|000000|iOS
needs-triage|FBCA04|Not looked at yet
needs-info|D4C5F9|Waiting on the reporter; closes automatically without a reply
auto-fix|5319E7|Ask Claude to open a pull request for this issue
LABELS

echo "Repository settings"
gh api --method PATCH "repos/$REPO" --silent \
  -F delete_branch_on_merge=true -F allow_auto_merge=true -F has_discussions=true
gh api --method PUT "repos/$REPO/vulnerability-alerts" --silent
gh api --method PUT "repos/$REPO/automated-security-fixes" --silent
# Lets the Nitro update workflow open pull requests.
gh api --method PUT "repos/$REPO/actions/permissions/workflow" --silent \
  -f default_workflow_permissions=read -F can_approve_pull_request_reviews=true

echo "Release environment, limited to main"
gh api --method PUT "repos/$REPO/environments/$RELEASE_ENV" --silent --input - <<'JSON'
{"deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}}
JSON
if ! gh api "repos/$REPO/environments/$RELEASE_ENV/deployment-branch-policies" --jq '.branch_policies[].name' | grep -qx main; then
  gh api --method POST "repos/$REPO/environments/$RELEASE_ENV/deployment-branch-policies" --silent -f name=main -f type=branch
fi

echo "Release deploy key"
if gh secret list --repo "$REPO" --env "$RELEASE_ENV" --json name --jq '.[].name' | grep -qx RELEASE_DEPLOY_KEY; then
  echo "  already configured"
else
  KEY_DIR="$(mktemp -d)"
  trap 'rm -rf "$KEY_DIR"' EXIT
  ssh-keygen -q -t ed25519 -N '' -C "release@$REPO" -f "$KEY_DIR/key"
  gh repo deploy-key add "$KEY_DIR/key.pub" --repo "$REPO" --allow-write --title 'Release workflow'
  gh secret set RELEASE_DEPLOY_KEY --repo "$REPO" --env "$RELEASE_ENV" < "$KEY_DIR/key"
fi

echo "Tag $FIRST_TAG"
if ! gh api "repos/$REPO/git/ref/tags/$FIRST_TAG" --silent 2>/dev/null; then
  gh api --method POST "repos/$REPO/git/refs" --silent -f "ref=refs/tags/$FIRST_TAG" -f "sha=$FIRST_TAG_COMMIT"
fi

echo "Protect main"
RULESET="$(cat <<'JSON'
{
  "name": "Protect main",
  "target": "branch",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
  "bypass_actors": [{"actor_type": "DeployKey", "bypass_mode": "always"}],
  "rules": [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": false,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": false
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": false,
        "required_status_checks": [{"context": "CI OK"}]
      }
    }
  ]
}
JSON
)"
RULESET_ID="$(gh api "repos/$REPO/rulesets" --jq '.[] | select(.name == "Protect main") | .id')"
if [[ -n "$RULESET_ID" ]]; then
  printf '%s' "$RULESET" | gh api --method PUT "repos/$REPO/rulesets/$RULESET_ID" --silent --input -
else
  printf '%s' "$RULESET" | gh api --method POST "repos/$REPO/rulesets" --silent --input -
fi

echo "Done. Finish the manual steps in docs/AUTOMATION.md."
