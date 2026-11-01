#!/usr/bin/env python3
"""Post a Block Kit message to Slack. Stdlib only; never fails the calling job."""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

API_URL = "https://slack.com/api/chat.postMessage"
SECTION_LIMIT = 3000
HEADER_LIMIT = 150
CLIP_MARKER = "\n_... clipped_"
MARKERS = {
    "critical": ":rotating_light:",
    "warning": ":warning:",
    "info": ":information_source:",
}


def clip(text, limit, marker=CLIP_MARKER):
    """Return text trimmed so that text plus marker fits within limit."""
    if len(text) <= limit:
        return text
    return text[: limit - len(marker)].rstrip() + marker


def escape(text):
    """Escape the three characters Slack treats as control syntax in mrkdwn."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def is_web_url(url):
    return urllib.parse.urlparse(url).scheme in ("http", "https")


def pick_channel(severity, channel, alerts_channel):
    """Critical goes to the alerts channel; everything else to the project channel."""
    if severity == "critical":
        return alerts_channel.strip()
    return channel.strip()


def build_payload(channel, severity, title, body, repo, workflow, ref, link_url, link_text):
    marker = MARKERS.get(severity, MARKERS["info"])
    header = clip(f"{marker} {title}", HEADER_LIMIT, "...")
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": header, "emoji": True}},
        {
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"*{escape(repo)}* | {escape(workflow)} | `{escape(ref)}`"},
            ],
        },
    ]
    if body.strip():
        blocks.append(
            {"type": "section", "text": {"type": "mrkdwn", "text": clip(escape(body), SECTION_LIMIT)}}
        )
    if link_url and is_web_url(link_url):
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": link_text or "View run"},
                        "url": link_url,
                    }
                ],
            }
        )
    return {
        "channel": channel,
        "text": escape(f"{marker} {title} ({repo})"),
        "blocks": blocks,
        "unfurl_links": False,
    }


def post(token, payload, timeout=15):
    request = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def write_outputs(path, ts, channel):
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(f"ts={ts}\nchannel={channel}\n")


def run(env):
    """Send the notification described by env. Returns (ts, channel); both empty when skipped."""
    token = env.get("SLACK_BOT_TOKEN", "")
    if not token.strip():
        print("::notice::SLACK_BOT_TOKEN is not set; skipping Slack notification.")
        return "", ""

    severity = env.get("SEVERITY", "info").strip() or "info"
    if severity not in MARKERS:
        print(f"::warning::Unknown severity '{severity}'; using info.")
        severity = "info"

    channel = pick_channel(
        severity, env.get("SLACK_CHANNEL", ""), env.get("SLACK_ALERTS_CHANNEL", "alerts")
    )
    if not channel:
        print(f"::notice::No Slack channel for severity '{severity}'; skipping.")
        return "", ""

    body = env.get("BODY", "")
    body_file = env.get("BODY_FILE", "").strip()
    if body_file:
        try:
            with open(body_file, encoding="utf-8", errors="replace") as handle:
                body = handle.read()
        except OSError as error:
            print(f"::warning::Could not read body-file: {type(error).__name__}")
            body = ""

    server = env.get("GITHUB_SERVER_URL", "https://github.com")
    repo = env.get("GITHUB_REPOSITORY", "")
    run_id = env.get("GITHUB_RUN_ID", "")
    default_link = f"{server}/{repo}/actions/runs/{run_id}" if repo and run_id else ""
    payload = build_payload(
        channel=channel,
        severity=severity,
        title=env.get("TITLE", "").strip() or "Notification",
        body=body,
        repo=repo or "unknown repo",
        workflow=env.get("GITHUB_WORKFLOW", "workflow"),
        ref=env.get("GITHUB_REF_NAME", ""),
        link_url=env.get("LINK_URL", "").strip() or default_link,
        link_text=env.get("LINK_TEXT", "").strip() or "View run",
    )

    try:
        result = post(token, payload)
    except (urllib.error.URLError, OSError, ValueError) as error:
        print(f"::warning::Slack request failed: {type(error).__name__}")
        return "", ""

    if not result.get("ok"):
        print(f"::warning::Slack API error: {result.get('error', 'unknown')}")
        return "", ""

    return str(result.get("ts", "")), str(result.get("channel", channel))


def main():
    ts, channel = run(os.environ)
    write_outputs(os.environ.get("GITHUB_OUTPUT"), ts, channel)
    return 0


if __name__ == "__main__":
    sys.exit(main())
