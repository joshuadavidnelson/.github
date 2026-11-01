import importlib.util
import io
import json
import os
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from unittest import mock

SCRIPT = os.path.join(
    os.path.dirname(__file__), "..", "actions", "slack-notify", "slack_notify.py"
)
spec = importlib.util.spec_from_file_location("slack_notify", SCRIPT)
slack_notify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(slack_notify)

BASE_ENV = {
    "SLACK_BOT_TOKEN": "xoxb-test",
    "SLACK_CHANNEL": "my-repo",
    "SLACK_ALERTS_CHANNEL": "alerts",
    "SEVERITY": "warning",
    "TITLE": "Scan finished",
    "BODY": "3 findings",
    "GITHUB_REPOSITORY": "owner/repo",
    "GITHUB_WORKFLOW": "Deps audit",
    "GITHUB_REF_NAME": "main",
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_RUN_ID": "42",
}


def fake_response(data):
    response = mock.MagicMock()
    response.read.return_value = json.dumps(data).encode("utf-8")
    response.__enter__.return_value = response
    return response


def run_captured(env):
    out = io.StringIO()
    with redirect_stdout(out):
        result = slack_notify.run(env)
    return result, out.getvalue()


class PayloadTests(unittest.TestCase):
    def build(self, **overrides):
        args = dict(
            channel="C1",
            severity="critical",
            title="Leak found",
            body="details",
            repo="owner/repo",
            workflow="Secret scan",
            ref="main",
            link_url="https://example.com/run",
            link_text="View run",
        )
        args.update(overrides)
        return slack_notify.build_payload(**args)

    def test_block_shape(self):
        payload = self.build()
        types = [block["type"] for block in payload["blocks"]]
        self.assertEqual(types, ["header", "context", "section", "actions"])
        self.assertIn(":rotating_light:", payload["blocks"][0]["text"]["text"])
        self.assertIn("Leak found", payload["blocks"][0]["text"]["text"])
        context = payload["blocks"][1]["elements"][0]["text"]
        for part in ("owner/repo", "Secret scan", "main"):
            self.assertIn(part, context)
        button = payload["blocks"][3]["elements"][0]
        self.assertEqual(button["url"], "https://example.com/run")
        self.assertEqual(payload["channel"], "C1")

    def test_fallback_text(self):
        payload = self.build()
        self.assertIn("Leak found", payload["text"])
        self.assertIn("owner/repo", payload["text"])

    def test_empty_body_omits_section(self):
        payload = self.build(body="  ")
        types = [block["type"] for block in payload["blocks"]]
        self.assertNotIn("section", types)

    def test_no_link_omits_button(self):
        payload = self.build(link_url="")
        types = [block["type"] for block in payload["blocks"]]
        self.assertNotIn("actions", types)

    def test_body_is_clipped_with_marker(self):
        payload = self.build(body="x" * 5000)
        text = payload["blocks"][2]["text"]["text"]
        self.assertLessEqual(len(text), 3000)
        self.assertTrue(text.endswith(slack_notify.CLIP_MARKER))

    def test_short_body_is_untouched(self):
        payload = self.build(body="short")
        self.assertEqual(payload["blocks"][2]["text"]["text"], "short")

    def test_header_is_clipped(self):
        payload = self.build(title="t" * 400)
        self.assertLessEqual(len(payload["blocks"][0]["text"]["text"]), 150)


class RoutingTests(unittest.TestCase):
    def test_critical_goes_to_alerts(self):
        self.assertEqual(slack_notify.pick_channel("critical", "proj", "alerts"), "alerts")

    def test_warning_and_info_go_to_project(self):
        self.assertEqual(slack_notify.pick_channel("warning", "proj", "alerts"), "proj")
        self.assertEqual(slack_notify.pick_channel("info", "proj", "alerts"), "proj")

    def test_run_posts_critical_to_alerts_channel(self):
        env = dict(BASE_ENV, SEVERITY="critical")
        with mock.patch("urllib.request.urlopen") as urlopen:
            urlopen.return_value = fake_response({"ok": True, "ts": "1.2", "channel": "CA"})
            (ts, channel), _ = run_captured(env)
        sent = json.loads(urlopen.call_args[0][0].data)
        self.assertEqual(sent["channel"], "alerts")
        self.assertEqual((ts, channel), ("1.2", "CA"))

    def test_run_posts_warning_to_project_channel(self):
        with mock.patch("urllib.request.urlopen") as urlopen:
            urlopen.return_value = fake_response({"ok": True, "ts": "1.2", "channel": "CP"})
            run_captured(BASE_ENV)
        sent = json.loads(urlopen.call_args[0][0].data)
        self.assertEqual(sent["channel"], "my-repo")

    def test_empty_project_channel_skips_warning(self):
        env = dict(BASE_ENV, SLACK_CHANNEL="")
        with mock.patch("urllib.request.urlopen") as urlopen:
            result, out = run_captured(env)
        urlopen.assert_not_called()
        self.assertEqual(result, ("", ""))
        self.assertIn("::notice::", out)

    def test_default_link_is_run_url(self):
        with mock.patch("urllib.request.urlopen") as urlopen:
            urlopen.return_value = fake_response({"ok": True, "ts": "1", "channel": "C"})
            run_captured(BASE_ENV)
        sent = json.loads(urlopen.call_args[0][0].data)
        button = sent["blocks"][-1]["elements"][0]
        self.assertEqual(button["url"], "https://github.com/owner/repo/actions/runs/42")


class RunTests(unittest.TestCase):
    def test_empty_token_skips_with_notice(self):
        for token in ("", "   "):
            env = dict(BASE_ENV, SLACK_BOT_TOKEN=token)
            with mock.patch("urllib.request.urlopen") as urlopen:
                result, out = run_captured(env)
            urlopen.assert_not_called()
            self.assertEqual(result, ("", ""))
            self.assertIn("::notice::", out)

    def test_missing_token_skips(self):
        env = {k: v for k, v in BASE_ENV.items() if k != "SLACK_BOT_TOKEN"}
        with mock.patch("urllib.request.urlopen") as urlopen:
            result, _ = run_captured(env)
        urlopen.assert_not_called()
        self.assertEqual(result, ("", ""))

    def test_token_sent_as_bearer_header(self):
        with mock.patch("urllib.request.urlopen") as urlopen:
            urlopen.return_value = fake_response({"ok": True, "ts": "1", "channel": "C"})
            run_captured(BASE_ENV)
        request = urlopen.call_args[0][0]
        self.assertEqual(request.get_header("Authorization"), "Bearer xoxb-test")

    def test_ok_false_warns_and_returns_empty(self):
        with mock.patch("urllib.request.urlopen") as urlopen:
            urlopen.return_value = fake_response({"ok": False, "error": "channel_not_found"})
            result, out = run_captured(BASE_ENV)
        self.assertEqual(result, ("", ""))
        self.assertIn("::warning::", out)
        self.assertIn("channel_not_found", out)

    def test_network_error_warns_and_does_not_raise(self):
        with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("down")):
            result, out = run_captured(BASE_ENV)
        self.assertEqual(result, ("", ""))
        self.assertIn("::warning::", out)

    def test_invalid_json_warns(self):
        bad = mock.MagicMock()
        bad.read.return_value = b"not json"
        bad.__enter__.return_value = bad
        with mock.patch("urllib.request.urlopen", return_value=bad):
            result, out = run_captured(BASE_ENV)
        self.assertEqual(result, ("", ""))
        self.assertIn("::warning::", out)

    def test_unknown_severity_falls_back_to_info(self):
        env = dict(BASE_ENV, SEVERITY="bogus")
        with mock.patch("urllib.request.urlopen") as urlopen:
            urlopen.return_value = fake_response({"ok": True, "ts": "1", "channel": "C"})
            _, out = run_captured(env)
        sent = json.loads(urlopen.call_args[0][0].data)
        self.assertEqual(sent["channel"], "my-repo")
        self.assertIn("::warning::", out)


class OutputTests(unittest.TestCase):
    def test_write_outputs(self):
        with tempfile.NamedTemporaryFile("r+", delete=False) as handle:
            path = handle.name
        try:
            slack_notify.write_outputs(path, "1.2", "C1")
            with open(path, encoding="utf-8") as check:
                self.assertEqual(check.read(), "ts=1.2\nchannel=C1\n")
        finally:
            os.unlink(path)

    def test_write_outputs_without_path_is_noop(self):
        slack_notify.write_outputs(None, "1", "C")


INJECTION = "<!channel> <!here> <@U123> <https://x|y> a&b"
ESCAPED = "&lt;!channel&gt; &lt;!here&gt; &lt;@U123&gt; &lt;https://x|y&gt; a&amp;b"


class EscapeTests(unittest.TestCase):
    def build(self, **overrides):
        args = dict(
            channel="C1",
            severity="warning",
            title="t",
            body="b",
            repo="owner/repo",
            workflow="wf",
            ref="main",
            link_url="https://example.com/run",
            link_text="View run",
        )
        args.update(overrides)
        return slack_notify.build_payload(**args)

    def test_escape_helper(self):
        self.assertEqual(slack_notify.escape(INJECTION), ESCAPED)

    def test_title_escaped_in_fallback_text(self):
        payload = self.build(title=INJECTION)
        self.assertIn(ESCAPED, payload["text"])
        self.assertNotIn("<!channel>", payload["text"])

    def test_body_escaped(self):
        payload = self.build(body=INJECTION)
        self.assertEqual(payload["blocks"][2]["text"]["text"], ESCAPED)

    def test_context_fields_escaped(self):
        payload = self.build(repo=INJECTION, workflow=INJECTION, ref=INJECTION)
        context = payload["blocks"][1]["elements"][0]["text"]
        self.assertEqual(context.count(ESCAPED), 3)
        self.assertNotIn("<!", context)
        self.assertNotIn("<@", context)

    def test_repo_escaped_in_fallback_text(self):
        payload = self.build(repo=INJECTION)
        self.assertNotIn("<!channel>", payload["text"])

    def test_formatting_survives(self):
        payload = self.build(body="*bold* _italic_ `code`")
        self.assertEqual(payload["blocks"][2]["text"]["text"], "*bold* _italic_ `code`")

    def test_no_raw_mention_anywhere_in_serialized_payload(self):
        payload = self.build(title=INJECTION, body=INJECTION, repo=INJECTION,
                             workflow=INJECTION, ref=INJECTION)
        # The header is plain_text, which Slack does not parse for mentions.
        mrkdwn = [payload["text"]]
        mrkdwn.append(payload["blocks"][1]["elements"][0]["text"])
        mrkdwn.append(payload["blocks"][2]["text"]["text"])
        for text in mrkdwn:
            self.assertNotIn("<", text.replace("&lt;", ""))


class ButtonTests(unittest.TestCase):
    def build(self, **overrides):
        args = dict(
            channel="C1", severity="info", title="t", body="", repo="r",
            workflow="w", ref="main", link_url="https://example.com", link_text="View run",
        )
        args.update(overrides)
        return slack_notify.build_payload(**args)

    def button(self, payload):
        return payload["blocks"][-1]["elements"][0]

    def test_custom_link_text_on_button(self):
        payload = self.build(link_text="Open report")
        self.assertEqual(self.button(payload)["text"]["text"], "Open report")

    def test_default_link_text_via_run(self):
        with mock.patch("urllib.request.urlopen") as urlopen:
            urlopen.return_value = fake_response({"ok": True, "ts": "1", "channel": "C"})
            run_captured(BASE_ENV)
        sent = json.loads(urlopen.call_args[0][0].data)
        self.assertEqual(self.button(sent)["text"]["text"], "View run")

    def test_custom_link_text_via_run(self):
        with mock.patch("urllib.request.urlopen") as urlopen:
            urlopen.return_value = fake_response({"ok": True, "ts": "1", "channel": "C"})
            run_captured(dict(BASE_ENV, LINK_TEXT="Open report"))
        sent = json.loads(urlopen.call_args[0][0].data)
        self.assertEqual(self.button(sent)["text"]["text"], "Open report")

    def test_empty_link_text_falls_back_in_builder(self):
        payload = self.build(link_text="")
        self.assertEqual(self.button(payload)["text"]["text"], "View run")

    def test_non_http_link_omits_button(self):
        for url in ("javascript:alert(1)", "ftp://x/y", "slack://open", "not a url"):
            payload = self.build(link_url=url)
            types = [block["type"] for block in payload["blocks"]]
            self.assertNotIn("actions", types, url)

    def test_http_and_https_links_kept(self):
        for url in ("http://example.com", "https://example.com"):
            types = [block["type"] for block in self.build(link_url=url)["blocks"]]
            self.assertIn("actions", types, url)

    def test_non_http_link_still_posts(self):
        with mock.patch("urllib.request.urlopen") as urlopen:
            urlopen.return_value = fake_response({"ok": True, "ts": "9", "channel": "C"})
            (ts, _), _ = run_captured(dict(BASE_ENV, LINK_URL="javascript:alert(1)"))
        self.assertEqual(ts, "9")
        sent = json.loads(urlopen.call_args[0][0].data)
        self.assertNotIn("actions", [block["type"] for block in sent["blocks"]])


class HeaderAndDefaultsTests(unittest.TestCase):
    def sent(self, env):
        with mock.patch("urllib.request.urlopen") as urlopen:
            urlopen.return_value = fake_response({"ok": True, "ts": "1", "channel": "C"})
            run_captured(env)
        return json.loads(urlopen.call_args[0][0].data)

    def test_warning_marker(self):
        sent = self.sent(BASE_ENV)
        self.assertTrue(sent["blocks"][0]["text"]["text"].startswith(":warning: "))

    def test_info_marker(self):
        sent = self.sent(dict(BASE_ENV, SEVERITY="info"))
        self.assertTrue(
            sent["blocks"][0]["text"]["text"].startswith(":information_source: ")
        )

    def test_critical_marker(self):
        sent = self.sent(dict(BASE_ENV, SEVERITY="critical"))
        self.assertTrue(sent["blocks"][0]["text"]["text"].startswith(":rotating_light: "))

    def test_unfurl_links_disabled(self):
        self.assertIs(self.sent(BASE_ENV)["unfurl_links"], False)

    def test_default_title(self):
        for title in ("", "   "):
            sent = self.sent(dict(BASE_ENV, TITLE=title))
            self.assertIn("Notification", sent["blocks"][0]["text"]["text"])
            self.assertIn("Notification", sent["text"])


class BodyFileTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def write(self, content, name="body.txt"):
        path = os.path.join(self.dir.name, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def sent(self, env):
        with mock.patch("urllib.request.urlopen") as urlopen:
            urlopen.return_value = fake_response({"ok": True, "ts": "1", "channel": "C"})
            result, out = run_captured(env)
        return json.loads(urlopen.call_args[0][0].data), out

    def section(self, sent):
        return sent["blocks"][2]["text"]["text"]

    def test_body_file_is_read(self):
        path = self.write("from file")
        sent, _ = self.sent(dict(BASE_ENV, BODY_FILE=path))
        self.assertEqual(self.section(sent), "from file")

    def test_body_file_takes_precedence(self):
        path = self.write("from file")
        sent, _ = self.sent(dict(BASE_ENV, BODY="from env", BODY_FILE=path))
        self.assertEqual(self.section(sent), "from file")

    def test_body_file_is_clipped(self):
        path = self.write("x" * 9000)
        sent, _ = self.sent(dict(BASE_ENV, BODY_FILE=path))
        text = self.section(sent)
        self.assertLessEqual(len(text), 3000)
        self.assertTrue(text.endswith(slack_notify.CLIP_MARKER))

    def test_body_file_is_escaped(self):
        path = self.write(INJECTION)
        sent, _ = self.sent(dict(BASE_ENV, BODY_FILE=path))
        self.assertEqual(self.section(sent), ESCAPED)

    def test_missing_file_warns_and_still_posts(self):
        missing = os.path.join(self.dir.name, "nope.txt")
        with mock.patch("urllib.request.urlopen") as urlopen:
            urlopen.return_value = fake_response({"ok": True, "ts": "1", "channel": "C"})
            result, out = run_captured(dict(BASE_ENV, BODY_FILE=missing))
        self.assertIn("::warning::", out)
        self.assertEqual(result[0], "1")
        sent = json.loads(urlopen.call_args[0][0].data)
        self.assertNotIn("section", [block["type"] for block in sent["blocks"]])

    def test_missing_file_main_returns_zero(self):
        missing = os.path.join(self.dir.name, "nope.txt")
        env = dict(BASE_ENV, BODY_FILE=missing)
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch("urllib.request.urlopen") as urlopen:
            urlopen.return_value = fake_response({"ok": True, "ts": "1", "channel": "C"})
            out = io.StringIO()
            with redirect_stdout(out):
                code = slack_notify.main()
        self.assertEqual(code, 0)
        self.assertIn("::warning::", out.getvalue())


class MainNeverFailsTests(unittest.TestCase):
    def main_with(self, env, **patch):
        out = io.StringIO()
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch("urllib.request.urlopen", **patch), redirect_stdout(out):
            return slack_notify.main()

    def test_ok_false_returns_zero(self):
        code = self.main_with(
            BASE_ENV, return_value=fake_response({"ok": False, "error": "boom"})
        )
        self.assertEqual(code, 0)

    def test_network_error_returns_zero(self):
        code = self.main_with(BASE_ENV, side_effect=urllib.error.URLError("down"))
        self.assertEqual(code, 0)

    def test_missing_token_returns_zero(self):
        env = {k: v for k, v in BASE_ENV.items() if k != "SLACK_BOT_TOKEN"}
        self.assertEqual(self.main_with(env), 0)

    def test_main_writes_outputs(self):
        with tempfile.NamedTemporaryFile("r+", delete=False) as handle:
            path = handle.name
        try:
            code = self.main_with(
                dict(BASE_ENV, GITHUB_OUTPUT=path),
                return_value=fake_response({"ok": True, "ts": "5", "channel": "CX"}),
            )
            with open(path, encoding="utf-8") as check:
                self.assertEqual(check.read(), "ts=5\nchannel=CX\n")
            self.assertEqual(code, 0)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
