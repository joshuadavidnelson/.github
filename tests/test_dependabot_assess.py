import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

SCRIPT = os.path.join(
    os.path.dirname(__file__), "..", "actions", "dependabot-assess", "assess.py"
)
spec = importlib.util.spec_from_file_location("assess", SCRIPT)
assess = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assess)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "dependabot")


def dep(name="lib", update="patch", dep_type="direct:production", **extra):
    entry = {
        "dependencyName": name,
        "dependencyType": dep_type,
        "updateType": "version-update:semver-%s" % update,
        "prevVersion": "1.0.0",
        "newVersion": "1.0.1",
    }
    entry.update(extra)
    return entry


def run(deps, title="Bump lib", **kwargs):
    return assess.assess(json.dumps(deps), title, **kwargs)


class VerdictTests(unittest.TestCase):
    def test_patch_is_low_risk(self):
        self.assertEqual(run([dep(update="patch")])["verdict"], "low-risk")

    def test_minor_production_needs_review(self):
        self.assertEqual(run([dep(update="minor")])["verdict"], "review")

    def test_minor_development_is_low_risk(self):
        result = run([dep(update="minor", dep_type="direct:development")])
        self.assertEqual(result["verdict"], "low-risk")

    def test_minor_github_actions_is_low_risk(self):
        result = run([dep(update="minor", packageEcosystem="github_actions")])
        self.assertEqual(result["verdict"], "low-risk")

    def test_major_is_risky_even_for_development(self):
        result = run([dep(update="major", dep_type="direct:development")])
        self.assertEqual(result["verdict"], "risky")

    def test_unknown_update_type_needs_review(self):
        entry = dep()
        entry["updateType"] = "version-update:something-new"
        self.assertEqual(run([entry])["verdict"], "review")

    def test_missing_update_type_needs_review(self):
        entry = dep()
        del entry["updateType"]
        self.assertEqual(run([entry])["verdict"], "review")

    def test_grouped_update_takes_worst_verdict(self):
        result = run([dep("a", "patch"), dep("b", "minor"), dep("c", "major")])
        self.assertEqual(result["verdict"], "risky")
        self.assertIn("c is a major", result["reasons"][0])

    def test_grouped_patches_stay_low_risk(self):
        self.assertEqual(run([dep("a"), dep("b")])["verdict"], "low-risk")

    def test_label_matches_verdict(self):
        self.assertEqual(run([dep(update="major")])["label"], "deps: risky")
        self.assertEqual(run([dep(update="minor")])["label"], "deps: review")
        self.assertEqual(run([dep()])["label"], "deps: low-risk")

    def test_empty_list_needs_review(self):
        self.assertEqual(run([])["verdict"], "review")

    def test_malformed_json_needs_review(self):
        for raw in ("not json", "{}", "[1, 2]", '"x"'):
            with self.subTest(raw=raw):
                result = assess.assess(raw, "Bump lib")
                self.assertEqual(result["verdict"], "review")

    def test_blank_json_needs_review(self):
        self.assertEqual(assess.assess("", "")["verdict"], "review")


class SecurityTests(unittest.TestCase):
    def test_title_marker(self):
        self.assertTrue(run([dep()], "[Security] Bump lib")["security"])
        self.assertTrue(run([dep()], "Bump lib for security fix")["security"])

    def test_package_names_containing_security_do_not_match(self):
        for title in (
            "Bump security-utils from 1.0.0 to 1.0.1",
            "Bump node-security from 1.0.0 to 1.0.1",
            "Bump securityfoo from 1.0.0 to 1.0.1",
        ):
            with self.subTest(title=title):
                self.assertFalse(run([dep()], title)["security"])

    def test_standalone_security_word_matches(self):
        for title in ("Security fix for lib", "Bump lib (security)", "[security] Bump lib"):
            with self.subTest(title=title):
                self.assertTrue(run([dep()], title)["security"])

    def test_plain_title_is_not_security(self):
        self.assertFalse(run([dep()], "Bump lib")["security"])

    def test_alert_state_and_ghsa(self):
        self.assertTrue(run([dep()], alert_state="FIXED")["security"])
        self.assertTrue(run([dep()], ghsa_id="GHSA-xxxx")["security"])
        self.assertTrue(run([dep(ghsaId="GHSA-xxxx")])["security"])

    def test_security_never_downgrades(self):
        result = run([dep(update="major")], "[Security] Bump lib", ghsa_id="GHSA-x")
        self.assertEqual(result["verdict"], "risky")
        result = run([dep(update="minor")], "[Security] Bump lib")
        self.assertEqual(result["verdict"], "review")

    def test_security_does_not_upgrade_low_risk(self):
        self.assertEqual(run([dep()], "[Security] Bump lib")["verdict"], "low-risk")


class CommentTests(unittest.TestCase):
    def comment(self, deps, title="Bump lib"):
        return assess.render_comment(run(deps, title))

    def test_marker_first_and_checks_line(self):
        text = self.comment([dep()])
        self.assertTrue(text.startswith("<!-- dependabot-check -->\n"))
        self.assertIn("Confirm this pull request's checks pass before merging", text)
        self.assertIn("**Verdict: low-risk**", text)

    def test_table_row(self):
        text = self.comment([dep("lodash", "minor")])
        self.assertIn("| lodash | 1.0.0 | 1.0.1 | direct:production | minor |", text)

    def test_security_flag_rendered(self):
        self.assertIn("Security update", self.comment([dep()], "[Security] Bump lib"))
        self.assertNotIn("Security update", self.comment([dep()]))

    def test_escapes_table_breakers(self):
        hostile = dep("a|b`c<img src=x>*_[x](y)\nline", "patch")
        hostile["newVersion"] = "1|2"
        text = self.comment([hostile])
        row = [l for l in text.splitlines() if l.startswith("| a")][0]
        self.assertEqual(row.count("|"), 6)
        for char in "`<>*[]":
            self.assertNotIn(char, row)
        self.assertNotIn("\n", row)
        reasons = [l for l in text.splitlines() if l.startswith("- ")]
        for line in reasons:
            self.assertNotIn("<", line)
            self.assertNotIn("`", line)

    def test_mentions_and_issue_refs_are_escaped(self):
        text = self.comment([dep("@types/node", "patch"), dep("@someuser #12", "patch")])
        for line in text.splitlines():
            if line.startswith("| ") or line.startswith("- "):
                self.assertNotIn("@", line)
                self.assertNotIn("#", line.replace("&#", ""))
        self.assertIn("&#64;types/node", text)
        self.assertEqual(assess.escape("@a#b"), "&#64;a&#35;b")

    def test_long_names_are_clipped(self):
        text = self.comment([dep("x" * 500)])
        self.assertNotIn("x" * 200, text)

    def test_row_cap(self):
        deps = [dep("d%d" % i) for i in range(assess.MAX_ROWS + 5)]
        text = self.comment(deps)
        self.assertIn("And 5 more not shown.", text)
        self.assertNotIn("| d%d |" % (assess.MAX_ROWS + 1), text)


class CliTests(unittest.TestCase):
    def run_cli(self, env):
        full = {k: v for k, v in os.environ.items() if k not in (
            "DEPENDENCIES_JSON", "PR_TITLE", "ALERT_STATE", "GHSA_ID", "COMMENT_FILE")}
        full.update(env)
        return subprocess.run(
            [sys.executable, SCRIPT], env=full, capture_output=True, text=True, check=True
        )

    def test_fixture_end_to_end(self):
        with open(os.path.join(FIXTURES, "grouped.json"), encoding="utf-8") as handle:
            raw = handle.read()
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "comment.md")
            proc = self.run_cli({
                "DEPENDENCIES_JSON": raw,
                "PR_TITLE": "Bump the npm group with 3 updates",
                "COMMENT_FILE": out,
            })
            result = json.loads(proc.stdout)
            self.assertEqual(result["verdict"], "risky")
            self.assertEqual(result["label"], "deps: risky")
            self.assertFalse(result["security"])
            self.assertEqual(sorted(result), ["label", "reasons", "security", "verdict"])
            with open(out, encoding="utf-8") as handle:
                self.assertIn("<!-- dependabot-check -->", handle.read())

    def test_no_comment_file_is_fine(self):
        proc = self.run_cli({"DEPENDENCIES_JSON": "[]", "PR_TITLE": ""})
        self.assertEqual(json.loads(proc.stdout)["verdict"], "review")


if __name__ == "__main__":
    unittest.main()
