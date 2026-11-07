# Automation

Everything except reviewing pull requests runs on its own.

| What happens | When | Where |
|---|---|---|
| Lint, types, unit, server and script tests, Android/iOS/web builds, package contents | Every PR and push to `main` | `ci.yml` |
| Device tests: Maestro on an Android emulator and iOS simulator, plus XCTests | Every PR and push to `main` | `ci.yml` (`e2e-android`, `e2e-ios`) |
| Builds against each supported Nitro runtime and the newest on npm | Android on every PR; both platforms on `main`, weekly | `ci.yml` |
| Publish to npm, tag, changelog, GitHub release, comment on fixed issues | After CI passes on `main`, if there are releasable commits | `release.yml` |
| Dependency update PRs | Weekly | `dependabot.yml` |
| Code scanning and dependency review | Every PR, weekly | `codeql.yml`, `ci.yml` |
| PR for a new Nitro runtime | Weekly, when one exists | `nitro-update.yml` |
| Label new issues; close `needs-info` issues after 21 quiet days | On open, daily | `issues.yml` |
| Fix an issue and open a PR | See [Issues to pull requests](#issues-to-pull-requests) | `claude.yml` |

## How a release is decided

Merging to `main` publishes without any further step, so **the merge is the release decision**. `scripts/release-bump.mjs` reads the commits since the last tag:

| Commits | Result |
|---|---|
| `feat:` | minor |
| `fix:`, `perf:`, `revert:` | patch |
| `docs:`, `chore:`, `ci:`, `test:`, `refactor:`, ... | no release |
| `feat!:` or a `BREAKING CHANGE:` footer | major, or minor while on 0.x |

Check the PR title before a squash merge, because it becomes the commit message. Dependency updates use `chore(deps)` and don't release, since this package has no runtime dependencies.

Moving to 1.0.0 is never automatic: run the **Release** workflow by hand with `major`. The same workflow previews a release when `dry-run` is on, and retries one that failed.

## Issues to pull requests

Claude works on an issue and opens a PR when:

- you or a collaborator opens the issue,
- you add the `auto-fix` label to anyone else's issue, or
- you or a collaborator comments `@claude` on an issue or PR.

Outsiders' issues need the label because their text is untrusted input on a public repository, and because anyone could otherwise spend your API credit. Read the issue before labelling it: the agent runs with your API key and can run the repository's tests. Agent PRs go through the same CI and your review, and the agent can't merge or publish.

## One-time setup

1. Run `scripts/setup-repo.sh`. It creates the labels, the `npm-publish` environment, a deploy key for release commits, the `v0.1.0` tag and the `main` ruleset, which requires a PR and the `CI OK` check. Only the deploy key may push to `main` directly.
2. On [npmjs.com](https://www.npmjs.com/package/@rs-native-kit/security/access), add a **trusted publisher**: GitHub Actions, repository `rajssinde/rs-native-kit-security`, workflow `release.yml`, environment `npm-publish`.
3. For issue automation, run `/install-github-app` in Claude Code, or install the [Claude GitHub App](https://github.com/apps/claude) and set the `ANTHROPIC_API_KEY` repository secret.
4. To publish `@rs-native-kit/security-server` as well, publish it once by hand (`cd server && npm publish --access public`), add the same trusted publisher for it, and set the repository variable `PUBLISH_SERVER` to `true`.

Until steps 1 and 2 are done, a release fails safely and publishes nothing.

## Running the checks locally

```sh
yarn verify                      # lint, types, unit, server, package contents
scripts/verify.sh android        # also native unit tests and an Android build
scripts/verify.sh ios            # also XCTests and an iOS Release build
scripts/verify.sh e2e-android    # Maestro on the booted emulator
scripts/verify.sh e2e-ios        # Maestro on the booted simulator
scripts/verify.sh all
```

The device tests need [Maestro](https://maestro.dev) and a clean device: `example/e2e/android.yaml` expects an emulator image without `su`, such as a Play Store image. On a path containing a space, such as iCloud Drive, the iOS steps run in a temporary copy of the repo because `pod install` fails there otherwise.
