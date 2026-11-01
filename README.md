# .github

Reusable GitHub Actions workflows, composite actions and starter files for my repositories. Community health files (issue templates, PR template, security policy) live in `.github/` as usual.

## What this repo provides

- Reusable workflows in `.github/workflows/`: secret scan, workflow lint, CodeQL, dependency audit and Dependabot check.
- Composite actions in `actions/`: `slack-notify`, `wordfence-scan` and `dependabot-assess`.
- Caller stubs in `templates/callers/` and `dependabot.yml` files per stack in `templates/dependabot/` (`wp-plugin`, `wp-site`, `node`; Workers use `node`).

Dependabot PRs are never merged automatically. `dependabot-check` comments a verdict and sets a `deps: low-risk`, `deps: review` or `deps: risky` label; I review and merge each one.

## Slack routing

Critical findings go to `#alerts`. Everything else goes to the project channel, named after the repo and set through the `SLACK_CHANNEL` repository variable. Pull request runs report through the check result only.

## Adopting in a repo

1. Copy the callers you want from `templates/callers/` into `.github/workflows/`, and replace `__SHA__` with a full commit SHA of this repo. The callers fail until this repo has a `v1` tag (see Releasing).
2. Copy the matching file from `templates/dependabot/` to `.github/dependabot.yml`.
3. Add the `SLACK_BOT_TOKEN` Actions secret and the `SLACK_CHANNEL` Actions variable.
4. For WordPress sites, add the `WORDFENCE_API_KEY` Actions secret and set `wordfence: true` in the `deps-audit` caller.
5. Optional: add `DEPENDABOT_ALERTS_TOKEN` as a Dependabot secret (a fine-grained token with Dependabot alerts read) so `dependabot-check` can flag security updates.
6. Invite the bot to `#alerts` and the project channel.
7. In the project channel, run `/github subscribe owner/repo` for repository activity.

## Labels

`deps-audit` creates `security-scan` and keeps one open issue with it, so Issues must be enabled. `dependabot-check` creates `deps: low-risk`, `deps: review` and `deps: risky`.

## Reusable workflows

Callers set `permissions: {}` at the top and grant the listed permissions on the calling job. `slack-channel` and `alerts-channel` (default `alerts`) are inputs wherever Slack is listed.

| Workflow | Inputs | Secrets | Caller permissions |
| --- | --- | --- | --- |
| `secret-scan` | `slack-channel`, `alerts-channel` | `SLACK_BOT_TOKEN`, `GITLEAKS_LICENSE` (organizations only) | `contents: read`, `pull-requests: read` |
| `workflow-lint` | none | none | `contents: read` |
| `codeql` | `languages` (default `actions`) | none | `actions: read`, `contents: read`, `security-events: write` |
| `deps-audit` | `composer`, `npm` (`auto`, `true`, `false`), `wordfence`, `composer-lock`, `extra-slugs`, `wp-core`, `php-version`, `node-version`, `slack-channel`, `alerts-channel` | `SLACK_BOT_TOKEN`, `WORDFENCE_API_KEY` | `contents: read`, `issues: write` |
| `dependabot-check` | none | `DEPENDABOT_ALERTS_TOKEN` | `contents: read`, `pull-requests: write`, `issues: write` |
| `slack-notify` | `slack-channel`, `alerts-channel`, `severity`, `title`, `body`, `link-url`, `link-text` | `SLACK_BOT_TOKEN` | none |

## Releasing

The reusable workflows load this repo's actions at `@v1`. After merging to `main`, move the tag to the merge commit:

```bash
git tag -f v1 <sha> && git push -f origin v1
```

## Limits

- CodeQL needs a public repository on free plans and has no PHP support.
- Dependabot-triggered runs cannot read normal secrets, so `dependabot-check` never posts to Slack.
- Slack steps are skipped, with a notice in the log, when no token is set.
