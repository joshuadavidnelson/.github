#!/usr/bin/env python3
"""Rate a Dependabot pull request and render the review comment.

Reads from the environment:
  DEPENDENCIES_JSON  fetch-metadata `updated-dependencies-json`
  PR_TITLE           pull request title
  ALERT_STATE        fetch-metadata `alert-state` (optional)
  GHSA_ID            fetch-metadata `ghsa-id` (optional)
  COMMENT_FILE       where to write the markdown comment (optional)

Prints {"verdict", "label", "reasons", "security"} as JSON on stdout. Never
approves or merges anything; it only classifies.
"""
import json
import os
import re
import sys

MARKER = "<!-- dependabot-check -->"

LABELS = {
    "low-risk": "deps: low-risk",
    "review": "deps: review",
    "risky": "deps: risky",
}
RANK = {"low-risk": 0, "review": 1, "risky": 2}
MAX_ROWS = 50
MAX_CELL = 80

# The standalone word only, so package names like security-utils or
# node-security do not match.
SECURITY_TITLE = re.compile(
    r"\[security\]|(?<![A-Za-z0-9-])security(?![A-Za-z0-9-])", re.IGNORECASE
)
# Anything markdown or HTML could interpret inside a table cell becomes a
# numeric entity, which renders as the literal character.
# @ and # are escaped so package names never mention users or link issues.
UNSAFE = re.compile(r"[&<>|`*_\[\]\\~!@#]")


def escape(value):
    text = " ".join(str(value if value is not None else "").split())
    if len(text) > MAX_CELL:
        text = text[: MAX_CELL - 1] + "…"
    return UNSAFE.sub(lambda m: "&#%d;" % ord(m.group()), text)


def short_update_type(update_type):
    return str(update_type or "").replace("version-update:semver-", "") or "unknown"


def rate_dependency(dep):
    """Return (verdict, reason) for one updated dependency."""
    name = escape(dep.get("dependencyName") or "unknown")
    update = dep.get("updateType") or ""
    dep_type = dep.get("dependencyType") or ""
    ecosystem = dep.get("packageEcosystem") or ""

    if update == "version-update:semver-major":
        return "risky", "%s is a major update." % name
    if update == "version-update:semver-minor":
        if ecosystem == "github_actions" or "development" in dep_type:
            return "low-risk", "%s is a minor update of a development dependency or action." % name
        return "review", "%s is a minor update of a production dependency." % name
    if update == "version-update:semver-patch":
        return "low-risk", "%s is a patch update." % name
    return "review", "%s has an unrecognized update type." % name


def is_security(deps, title, alert_state, ghsa_id):
    if alert_state.strip() or ghsa_id.strip():
        return True
    if any(d.get("alertState") or d.get("ghsaId") for d in deps):
        return True
    return bool(SECURITY_TITLE.search(title))


def parse_dependencies(raw):
    try:
        data = json.loads(raw) if raw.strip() else []
    except ValueError:
        return None
    if not isinstance(data, list) or not all(isinstance(d, dict) for d in data):
        return None
    return data


def assess(raw_json, title="", alert_state="", ghsa_id=""):
    deps = parse_dependencies(raw_json)
    if deps is None:
        return {
            "verdict": "review",
            "label": LABELS["review"],
            "reasons": ["The dependency metadata could not be read, so the update needs a manual look."],
            "security": bool(SECURITY_TITLE.search(title)) or bool(alert_state.strip() or ghsa_id.strip()),
            "dependencies": [],
        }
    if not deps:
        return {
            "verdict": "review",
            "label": LABELS["review"],
            "reasons": ["No dependency updates were reported, so the update needs a manual look."],
            "security": is_security([], title, alert_state, ghsa_id),
            "dependencies": [],
        }

    verdict = "low-risk"
    rated = []
    for dep in deps:
        dep_verdict, reason = rate_dependency(dep)
        if RANK[dep_verdict] > RANK[verdict]:
            verdict = dep_verdict
        if (dep_verdict, reason) not in rated:
            rated.append((dep_verdict, reason))

    # Worst findings first so a long grouped update leads with what matters.
    rated.sort(key=lambda item: -RANK[item[0]])
    reasons = [reason for _, reason in rated]
    security = is_security(deps, title, alert_state, ghsa_id)
    if security:
        reasons.append("This is a security update. The verdict is not lowered because of it.")

    return {
        "verdict": verdict,
        "label": LABELS[verdict],
        "reasons": reasons,
        "security": security,
        "dependencies": deps,
    }


def render_comment(result):
    deps = result["dependencies"]
    lines = [MARKER, "### Dependabot check", ""]
    if result["security"]:
        lines += ["> **Security update**", ""]
    if deps:
        lines += [
            "| Dependency | From | To | Type | Update |",
            "| --- | --- | --- | --- | --- |",
        ]
        for dep in deps[:MAX_ROWS]:
            lines.append(
                "| %s | %s | %s | %s | %s |"
                % (
                    escape(dep.get("dependencyName") or "unknown"),
                    escape(dep.get("prevVersion") or "-"),
                    escape(dep.get("newVersion") or "-"),
                    escape(dep.get("dependencyType") or "unknown"),
                    escape(short_update_type(dep.get("updateType"))),
                )
            )
        if len(deps) > MAX_ROWS:
            lines.append("")
            lines.append("And %d more not shown." % (len(deps) - MAX_ROWS))
        lines.append("")
    lines += ["**Verdict: %s**" % result["verdict"], ""]
    lines += ["- %s" % r for r in result["reasons"]]
    lines += [
        "",
        "Confirm this pull request's checks pass before merging. This check never approves or merges.",
    ]
    return "\n".join(lines) + "\n"


def main():
    result = assess(
        os.environ.get("DEPENDENCIES_JSON", ""),
        os.environ.get("PR_TITLE", ""),
        os.environ.get("ALERT_STATE", ""),
        os.environ.get("GHSA_ID", ""),
    )
    comment_file = os.environ.get("COMMENT_FILE", "")
    if comment_file:
        with open(comment_file, "w", encoding="utf-8") as handle:
            handle.write(render_comment(result))
    print(
        json.dumps(
            {k: result[k] for k in ("verdict", "label", "reasons", "security")}
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
