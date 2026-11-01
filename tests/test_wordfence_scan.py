import importlib.util
import json
import os
import tempfile
import contextlib
import gzip
import io
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures", "wordfence")
SCRIPT = os.path.join(HERE, "..", "actions", "wordfence-scan", "wordfence_scan.py")
spec = importlib.util.spec_from_file_location("wordfence_scan", SCRIPT)
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)

LOCK = os.path.join(FIXTURES, "composer.lock")
FEED = os.path.join(FIXTURES, "wordfence-feed.json")
EXTRA = "plugin:example-extra@2.0.3"


class CompareVersionsTest(unittest.TestCase):
    def test_ordering(self):
        cases = [
            ("1.2.3", "1.2.10", -1),
            ("2.0", "1.9.9", 1),
            ("4.14.5", "4.9", 1),
            ("28.8", "28.8.1", -1),
            ("1.0.1", "1.0", 1),
            ("1.0rc1", "1.0beta2", 1),
            ("1.0-beta1", "1.0", -1),
            ("1.0", "1.0-beta1", 1),
            ("1.0pl1", "1.0", 1),
        ]
        for left, right, expected in cases:
            with self.subTest(left=left, right=right):
                self.assertEqual(scan.compare_versions(left, right), expected)
                self.assertEqual(scan.compare_versions(right, left), -expected)

    def test_trailing_zero_parts_are_equal(self):
        self.assertEqual(scan.compare_versions("1.6", "1.6.0"), 0)
        self.assertEqual(scan.compare_versions("1.0.0", "1.0.0.0"), 0)


class InRangeTest(unittest.TestCase):
    def rng(self, low, high, low_inc=True, high_inc=True):
        return {"from_version": low, "from_inclusive": low_inc, "to_version": high, "to_inclusive": high_inc}

    def test_inclusive_bounds(self):
        self.assertTrue(scan.in_range("5.10.1", self.rng("*", "5.10.1")))
        self.assertTrue(scan.in_range("1.0", self.rng("1.0", "2.0")))

    def test_exclusive_bounds(self):
        self.assertFalse(scan.in_range("5.10.1", self.rng("*", "5.10.1", high_inc=False)))
        self.assertFalse(scan.in_range("1.0", self.rng("1.0", "2.0", low_inc=False)))
        self.assertTrue(scan.in_range("1.5", self.rng("1.0", "2.0", False, False)))

    def test_wildcards_are_open(self):
        self.assertTrue(scan.in_range("0.0.1", self.rng("*", "5.0")))
        self.assertTrue(scan.in_range("99.0", self.rng("1.0", "*")))
        self.assertTrue(scan.in_range("3.0", self.rng("*", "*")))

    def test_outside_range(self):
        self.assertFalse(scan.in_range("5.10.2", self.rng("*", "5.10.1")))
        self.assertFalse(scan.in_range("0.9", self.rng("1.0", "*")))


class LoadPackagesTest(unittest.TestCase):
    def test_mapping(self):
        packages = {(p[0], p[1]): p for p in scan.load_packages(LOCK)}
        self.assertEqual(packages[("plugin", "redirection")][2], "5.10.1")
        self.assertEqual(packages[("plugin", "wordpress-seo")][2], "28.8", "leading v is stripped")
        self.assertEqual(packages[("theme", "twentytwentyfour")][2], "1.6")
        self.assertEqual(packages[("core", "wordpress")][2], "7.1.4")
        self.assertFalse(packages[("plugin", "redirection")][4])

    def test_core_is_reported_once_and_other_packages_are_ignored(self):
        packages = scan.load_packages(LOCK)
        self.assertEqual(len([p for p in packages if p[0] == "core"]), 1)
        self.assertNotIn("composer/installers", [p[3] for p in packages])
        self.assertNotIn("wpackagist-plugin/not-deployed", [p[3] for p in packages])


class CoreAndLockTest(unittest.TestCase):
    def write_lock(self, tmp, packages):
        path = os.path.join(tmp, "composer.lock")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"packages": packages}, handle)
        return path

    def test_both_core_packages_are_recognised(self):
        self.assertIn("johnpbloch/wordpress-core", scan.CORE_PACKAGES)
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write_lock(tmp, [{"name": "johnpbloch/wordpress-core", "version": "6.8.1"}])
            self.assertEqual([p[:3] for p in scan.load_packages(path)], [("core", "wordpress", "6.8.1")])

    def test_feed_core_entry_matches_whatever_slug_it_carries(self):
        feed = {"c": {"id": "c", "title": "Core", "software": [{"type": "core", "slug": "wordpress-core",
            "affected_versions": {"a": {"from_version": "*", "to_version": "7.2"}}}]}}
        findings, _ = scan.find_vulnerabilities(feed, [("core", "wordpress", "7.1.4", "wordpress", False)])
        self.assertEqual([f["slug"] for f in findings], ["wordpress"])

    def test_lock_without_wordpress_packages_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write_lock(tmp, [{"name": "composer/installers", "version": "2.3.0"}])
            self.assertEqual(scan.load_packages(path), [])
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(scan.main([path, "--feed-file", FEED]), 2)

    def test_findings_are_sorted_by_package_then_id(self):
        def record(rid, slug):
            return (rid, {"id": rid, "title": "T", "software": [{"type": "plugin", "slug": slug,
                "affected_versions": {"a": {"from_version": "*", "to_version": "*"}}}]})
        feed = dict([record("2", "bbb"), record("3", "aaa"), record("1", "bbb")])
        packages = [("plugin", "aaa", "1", "plugin:aaa", True), ("plugin", "bbb", "1", "plugin:bbb", True)]
        findings, _ = scan.find_vulnerabilities(feed, packages)
        self.assertEqual([(f["package"], f["id"]) for f in findings],
                         [("plugin:aaa", "3"), ("plugin:bbb", "1"), ("plugin:bbb", "2")])


class ParseExtrasTest(unittest.TestCase):
    def test_entries_and_core(self):
        packages = scan.parse_extras("plugin:my-fork@v1.2.3, theme:my-theme@2.0\nplugin:other@0.1", "6.8.1")
        self.assertEqual(
            [(p[0], p[1], p[2], p[4]) for p in packages],
            [
                ("plugin", "my-fork", "1.2.3", True),
                ("theme", "my-theme", "2.0", True),
                ("plugin", "other", "0.1", True),
                ("core", "wordpress", "6.8.1", True),
            ],
        )

    def test_empty_input(self):
        self.assertEqual(scan.parse_extras("", ""), [])
        self.assertEqual(scan.parse_extras("  \n", "  "), [])

    def test_malformed_entry_is_an_error(self):
        for bad in ("my-fork@1.0", "plugin:my-fork", "widget:x@1.0", "plugin:Bad Slug@1"):
            with self.subTest(bad=bad), self.assertRaises(scan.ScanError):
                scan.parse_extras(bad)


class EndToEndTest(unittest.TestCase):
    def run_scan(self, feed_path, lock=LOCK, extra="", core=""):
        with tempfile.TemporaryDirectory() as tmp:
            report, summary = os.path.join(tmp, "r.md"), os.path.join(tmp, "s.json")
            argv = [lock, "--feed-file", feed_path, "--report", report, "--json", summary]
            if extra:
                argv += ["--extra-slugs", extra]
            if core:
                argv += ["--wp-core", core]
            code = scan.main(argv)
            if code == 2:
                return code, None, None
            with open(report, encoding="utf-8") as handle:
                text = handle.read()
            with open(summary, encoding="utf-8") as handle:
                data = json.load(handle)
        return code, text, data

    def test_findings(self):
        code, report, data = self.run_scan(FEED, extra=EXTRA)
        self.assertEqual(code, 1)
        ids = sorted(f["id"][-1] for f in data["findings"])
        # 1 redirection (inclusive bound), 3 extra package, 5 yoast wildcard, 9 core.
        self.assertEqual(ids, ["1", "3", "5", "9"])
        self.assertEqual(data["informational_skipped"], 1)
        extra = next(f for f in data["findings"] if f["slug"] == "example-extra")
        self.assertTrue(extra["extra"])
        self.assertIn("added by input", report)
        self.assertIn("CVE-2099-0001", report)
        self.assertIn("5.10.2", report)

    def test_extra_package_is_not_checked_unless_requested(self):
        code, _, data = self.run_scan(FEED)
        self.assertEqual(code, 1)
        self.assertNotIn("3", [f["id"][-1] for f in data["findings"]])

    def test_wp_core_input_alone_scans_without_a_lock_file(self):
        missing = os.path.join(FIXTURES, "no-such.lock")
        code, _, data = self.run_scan(FEED, lock=missing, core="7.1.4")
        self.assertEqual(code, 1)
        self.assertEqual([f["type"] for f in data["findings"]], ["core"])

    def test_missing_lock_without_extras_is_an_error(self):
        self.assertEqual(self.run_scan(FEED, lock=os.path.join(FIXTURES, "no-such.lock"))[0], 2)

    def test_clean_feed_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "feed.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"x": {"id": "x", "title": "Other", "software": [{"type": "plugin", "slug": "other",
                    "affected_versions": {"a": {"from_version": "*", "from_inclusive": True, "to_version": "*", "to_inclusive": True}}}]}}, handle)
            code, report, data = self.run_scan(path)
        self.assertEqual(code, 0)
        self.assertEqual(data["findings"], [])
        self.assertIn("No known vulnerabilities", report)

    def test_empty_feed_is_an_error_not_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "feed.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("{}")
            self.assertEqual(self.run_scan(path)[0], 2)

    def test_missing_or_malformed_input_is_an_error(self):
        self.assertEqual(self.run_scan(os.path.join(FIXTURES, "missing.json"))[0], 2)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "feed.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("<html>blocked</html>")
            self.assertEqual(self.run_scan(path)[0], 2)

    def test_missing_api_key_is_an_error(self):
        with mock.patch.dict(os.environ, {"WORDFENCE_API_KEY": ""}), \
                mock.patch.object(scan.urllib.request, "urlopen") as urlopen:
            self.assertEqual(scan.main([LOCK]), 2)
        urlopen.assert_not_called()

    def test_unexpected_exception_is_an_error_without_leaking_the_key(self):
        key = "sekret-key-123"
        err = io.StringIO()
        with mock.patch.dict(os.environ, {"WORDFENCE_API_KEY": key}), \
                mock.patch.object(scan, "fetch_feed", side_effect=RuntimeError(f"boom {key}")), \
                contextlib.redirect_stderr(err):
            self.assertEqual(scan.main([LOCK]), 2)
        self.assertIn("::error::", err.getvalue())
        self.assertIn("RuntimeError", err.getvalue())
        self.assertNotIn(key, err.getvalue())

    def test_numeric_version_bound_in_feed_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "feed.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"x": {"id": "x", "title": "T", "software": [{"type": "plugin", "slug": "redirection",
                    "affected_versions": {"a": {"from_version": 5, "to_version": "*"}}}]}}, handle)
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(self.run_scan(path)[0], 2)
        self.assertIn("non-string from_version", err.getvalue())

    def test_wrong_shaped_feed_is_an_error_not_clean(self):
        good_range = {"a": {"from_version": "*", "to_version": "*"}}
        cases = {
            "error body": {"error": "Invalid API key"},
            "record is a list": {"x": ["not", "a", "record"]},
            "list feed with a non-object": [1, 2],
            "missing software": {"x": {"id": "x", "title": "T"}},
            "software not a list": {"x": {"id": "x", "software": {"type": "plugin"}}},
            "software entry not an object": {"x": {"id": "x", "software": ["redirection"]}},
            "software without type": {"x": {"id": "x", "software": [{"slug": "redirection", "affected_versions": good_range}]}},
            "missing affected_versions": {"x": {"id": "x", "software": [{"type": "plugin", "slug": "redirection"}]}},
            "affected_versions a string": {"x": {"id": "x", "software": [{"type": "plugin", "slug": "redirection", "affected_versions": "all"}]}},
            "range not an object": {"x": {"id": "x", "software": [{"type": "plugin", "slug": "redirection", "affected_versions": {"a": "1.0"}}]}},
            "malformed range in an unrelated package": {"x": {"id": "x", "software": [{"type": "plugin", "slug": "other", "affected_versions": {"a": ["1.0"]}}]}},
        }
        for label, feed in cases.items():
            with self.subTest(label), tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "feed.json")
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(feed, handle)
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(self.run_scan(path)[0], 2)
                # A validation error, not the catch-all for an unexpected crash.
                self.assertIn("feed", err.getvalue())
                self.assertNotIn("crashed", err.getvalue())

    def test_corrupt_gzip_response_is_an_error(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b"not gzip data"
        response.headers = {"Content-Encoding": "gzip"}
        with mock.patch.dict(os.environ, {"WORDFENCE_API_KEY": "k"}), \
                mock.patch.object(scan.urllib.request, "urlopen", return_value=response), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(scan.main([LOCK]), 2)

    def test_gzip_response_is_decoded(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = gzip.compress(b'{"a": {"id": "a"}}')
        response.headers = {"Content-Encoding": "gzip"}
        with mock.patch.object(scan.urllib.request, "urlopen", return_value=response):
            self.assertEqual(scan.fetch_feed("k"), {"a": {"id": "a"}})

    def test_feed_text_cannot_inject_markdown_or_mentions(self):
        self.assertNotIn("@octocat", scan._cell("hi @octocat"))
        self.assertNotIn("|", scan._cell("a|b").replace("\\|", ""))


if __name__ == "__main__":
    unittest.main()
