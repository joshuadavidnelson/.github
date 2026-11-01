#!/usr/bin/env python3
"""Check the WordPress packages in composer.lock against the Wordfence Intelligence v3 feed.

composer audit only knows packagist advisories, which do not cover wpackagist plugins,
themes or WordPress core. This script fills that gap.

Exit codes: 0 no findings, 1 findings, 2 error (an unreachable or malformed feed is never "clean").

Usage:
    WORDFENCE_API_KEY=... wordfence_scan.py composer.lock [--report out.md] [--json out.json]
        [--extra-slugs "plugin:my-fork@1.2.3 theme:my-theme@2.0"] [--wp-core 6.8.1]
    wordfence_scan.py composer.lock --feed-file feed.json    # offline, for tests
"""

import argparse
import datetime
import gzip
import json
import os
import re
import sys
import urllib.error
import urllib.request

FEED_URL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner"
CORE_PACKAGES = ("johnpbloch/wordpress", "johnpbloch/wordpress-core")
EXTRA_PATTERN = re.compile(r"^(plugin|theme):([a-z0-9][a-z0-9._-]*)@(\S+)$")
ADVISORY_URL = "https://www.wordfence.com/threat-intel/vulnerabilities/id/"

# PHP version_compare() ordering of special forms; a bare number sorts above every named form.
_FORM_ORDER = {"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "rc": 3, "#": 4, "pl": 5, "p": 5}


class ScanError(Exception):
    """Raised for any condition that must not be reported as a clean scan."""


def _canonical(version):
    version = re.sub(r"[-_+]", ".", version.strip())
    version = re.sub(r"(\d)([^\d.])", r"\1.\2", version)
    version = re.sub(r"([^\d.])(\d)", r"\1.\2", version)
    return [part for part in version.split(".") if part != ""]


def _form_rank(part):
    if part.isdigit():
        return None
    for name, rank in _FORM_ORDER.items():
        if name != "#" and part.lower().startswith(name):
            return rank
    return -1


def _compare_parts(left, right):
    left_rank, right_rank = _form_rank(left), _form_rank(right)
    if left_rank is None and right_rank is None:
        return (int(left) > int(right)) - (int(left) < int(right))
    # A number compares as the "#" form against a named form.
    left_rank = _FORM_ORDER["#"] if left_rank is None else left_rank
    right_rank = _FORM_ORDER["#"] if right_rank is None else right_rank
    return (left_rank > right_rank) - (left_rank < right_rank)


def compare_versions(left, right):
    """Return -1, 0 or 1 like PHP's version_compare(), which WordPress uses.

    Unlike PHP, trailing ".0" parts are ignored so that 1.6 equals 1.6.0.
    """
    a, b = _strip_zeros(_canonical(left)), _strip_zeros(_canonical(right))
    for index in range(min(len(a), len(b))):
        result = _compare_parts(a[index], b[index])
        if result:
            return result
    if len(a) == len(b):
        return 0
    # One side has extra parts: a number makes it newer, a pre-release tag makes it older.
    longer, direction = (a, 1) if len(a) > len(b) else (b, -1)
    extra = next((p for p in longer[min(len(a), len(b)):] if not (p.isdigit() and int(p) == 0)), "0")
    if extra.isdigit() or _form_rank(extra) > _FORM_ORDER["#"]:
        return direction
    return -direction


def _strip_zeros(parts):
    while parts and parts[-1].isdigit() and int(parts[-1]) == 0:
        parts = parts[:-1]
    return parts


def in_range(version, rng):
    """True when version falls inside one affected range; "*" or empty bounds are open."""
    low, high = rng.get("from_version"), rng.get("to_version")
    if low not in (None, "", "*"):
        order = compare_versions(version, low)
        if order < 0 or (order == 0 and not rng.get("from_inclusive", True)):
            return False
    if high not in (None, "", "*"):
        order = compare_versions(version, high)
        if order > 0 or (order == 0 and not rng.get("to_inclusive", True)):
            return False
    return True


def _ranges(software):
    """Return the affected ranges of one software entry, rejecting any other shape."""
    affected = software.get("affected_versions")
    if isinstance(affected, dict):
        ranges = list(affected.values())
    elif isinstance(affected, list):
        ranges = affected
    else:
        raise ScanError("feed software entry has no affected_versions object")
    for rng in ranges:
        if not isinstance(rng, dict):
            raise ScanError("feed affected range is not an object")
        for bound in ("from_version", "to_version"):
            if rng.get(bound) is not None and not isinstance(rng[bound], str):
                raise ScanError(f"feed affected range has a non-string {bound}")
    return ranges


def _release_version(name, version):
    """Reject Composer branch and alias versions, which sort below every numeric bound and would read as clean."""
    lowered = version.lower()
    if not version[:1].isdigit() or lowered.endswith("-dev") or " as " in lowered:
        raise ScanError(f"cannot check {name}: {version!r} is a branch or alias version, not a release")
    return version


def load_packages(lock_path):
    """Map composer.lock packages to (type, slug, version, composer name, is_extra) tuples."""
    try:
        with open(lock_path, encoding="utf-8") as handle:
            lock = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ScanError(f"cannot read {lock_path}: {exc}") from exc
    packages = []
    for package in lock.get("packages", []):
        name, version = package.get("name", ""), str(package.get("version", "")).lstrip("vV")
        if not version:
            continue
        if name.startswith("wpackagist-plugin/"):
            packages.append(("plugin", name.split("/", 1)[1], _release_version(name, version), name, False))
        elif name.startswith("wpackagist-theme/"):
            packages.append(("theme", name.split("/", 1)[1], _release_version(name, version), name, False))
        elif name in CORE_PACKAGES:
            packages.append(("core", "wordpress", _release_version(name, version), name, False))
    return _unique(packages)


def parse_extras(text, wp_core=""):
    """Parse "plugin:slug@version" entries (space, comma or newline separated) and a core version."""
    packages = []
    for token in re.split(r"[\s,]+", text or ""):
        if not token:
            continue
        match = EXTRA_PATTERN.match(token)
        if not match:
            raise ScanError(f"invalid extra-slugs entry {token!r}; expected plugin:slug@version or theme:slug@version")
        kind, slug, version = match.groups()
        version = _release_version(f"{kind}:{slug}", version.lstrip("vV"))
        packages.append((kind, slug, version, f"{kind}:{slug}", True))
    core = (wp_core or "").strip().lstrip("vV")
    if core:
        packages.append(("core", "wordpress", _release_version("wordpress", core), "wordpress", True))
    return packages


def _unique(packages):
    # johnpbloch/wordpress is a metapackage of wordpress-core; report each core version once.
    seen, unique = set(), []
    for entry in packages:
        key = entry[:3]
        if key not in seen:
            seen.add(key)
            unique.append(entry)
    return unique


def _records(feed):
    if isinstance(feed, dict):
        records = list(feed.items())
    elif isinstance(feed, list):
        records = [(record.get("id", "") if isinstance(record, dict) else "", record) for record in feed]
    else:
        raise ScanError("feed is neither a JSON object nor a list")
    # An error body such as {"error": "Invalid API key"} is valid JSON but not a feed.
    for _, record in records:
        if not isinstance(record, dict) or not isinstance(record.get("software"), list):
            raise ScanError("feed contains a record without a software list")
        for software in record["software"]:
            if not isinstance(software, dict) or not isinstance(software.get("type"), str):
                raise ScanError("feed contains a malformed software entry")
            _ranges(software)
    return records


def find_vulnerabilities(feed, packages):
    """Return (findings, informational_skipped) for the packages against the feed."""
    records = _records(feed)
    if not records:
        raise ScanError("feed contains no records")
    wanted = {}
    for entry in packages:
        wanted.setdefault((entry[0], entry[1]), []).append(entry)
    findings, skipped = [], 0
    for key, record in records:
        for software in record["software"]:
            # Core entries are keyed by type alone; the feed's core slug is "wordpress".
            kind, slug = software.get("type"), software.get("slug")
            if kind == "core":
                slug = "wordpress"
            for _, _, version, name, is_extra in wanted.get((kind, slug), []):
                if any(in_range(version, rng) for rng in _ranges(software)):
                    if record.get("informational") or software.get("informational"):
                        skipped += 1
                        continue
                    findings.append(_finding(key, record, software, name, kind, slug, version, is_extra))
    findings.sort(key=lambda f: (f["package"], f["id"]))
    return findings, skipped


def _finding(key, record, software, name, kind, slug, version, is_extra):
    patched = software.get("patched_versions")
    if isinstance(patched, dict):
        patched = list(patched.keys())
    cve = record.get("cve")
    cvss = record.get("cvss")
    return {
        "id": str(record.get("id") or key),
        "package": name,
        "type": kind,
        "slug": slug,
        "version": version,
        "extra": is_extra,
        "title": str(record.get("title") or ""),
        "cve": cve if isinstance(cve, str) else "",
        "cvss_score": cvss.get("score") if isinstance(cvss, dict) else None,
        "patched_versions": patched if isinstance(patched, list) else [],
    }


def _cell(text):
    """Neutralise text from the feed before it lands in Markdown or an issue body."""
    text = re.sub(r"\s+", " ", str(text)).replace("|", "\\|").replace("`", "'")
    return text.replace("@", "@​")


def render_report(findings, packages, skipped, date):
    lines = [f"## Wordfence scan ({date})", ""]
    lines.append(f"Checked {len(packages)} packages against the Wordfence Intelligence v3 scanner feed.")
    if skipped:
        lines.append(f"Skipped {skipped} informational record(s).")
    lines.append("")
    if not findings:
        lines.append("No known vulnerabilities affect the locked versions.")
        return "\n".join(lines) + "\n"
    lines += ["| Package | Version | Vulnerability | CVE | Patched in |", "| --- | --- | --- | --- | --- |"]
    for item in findings:
        package = _cell(item["package"]) + (" (added by input)" if item["extra"] else "")
        title = f"[{_cell(item['title'])}]({ADVISORY_URL}{_cell(item['id'])})"
        patched = ", ".join(_cell(p) for p in item["patched_versions"]) or "no fix listed"
        lines.append(f"| {package} | {_cell(item['version'])} | {title} | {_cell(item['cve']) or '-'} | {patched} |")
    lines.append("")
    if any(item["extra"] for item in findings):
        lines.append("Packages added by input are matched by slug and version only; confirm they are the wordpress.org releases.")
    return "\n".join(lines) + "\n"


def fetch_feed(api_key):
    request = urllib.request.Request(
        FEED_URL,
        headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json", "Accept-Encoding": "gzip"},
    )
    try:
        with urllib.request.urlopen(request, timeout=300) as response:  # noqa: S310 (fixed https URL)
            body = response.read()
            if response.headers.get("Content-Encoding") == "gzip":
                body = gzip.decompress(body)
    except urllib.error.HTTPError as exc:
        # Report the status only; the response body and request headers can echo the key.
        raise ScanError(f"Wordfence feed request failed with HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError, EOFError) as exc:
        raise ScanError(f"Wordfence feed request failed: {type(exc).__name__}") from None
    try:
        return json.loads(body)
    except ValueError:
        raise ScanError("Wordfence feed response is not valid JSON") from None


def main(argv=None):
    """Run the scan; any unexpected exception becomes exit code 2, never a traceback or a clean result."""
    try:
        return _run(argv)
    except Exception as exc:  # noqa: BLE001 (a crash must never read as a clean scan)
        message = str(exc).replace(os.environ.get("WORDFENCE_API_KEY", "").strip() or "\0", "***")
        print(f"::error::Wordfence scan crashed: {type(exc).__name__}: {message}", file=sys.stderr)
        return 2


def _run(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("lock", help="path to composer.lock")
    parser.add_argument("--extra-slugs", default="", help="extra packages as plugin:slug@version or theme:slug@version")
    parser.add_argument("--wp-core", default="", help="WordPress core version to check in addition to the lock file")
    parser.add_argument("--feed-file", help="read the feed from this JSON file instead of the API")
    parser.add_argument("--report", help="write the Markdown report here (default: stdout)")
    parser.add_argument("--json", dest="json_out", help="write the JSON summary here")
    args = parser.parse_args(argv)

    try:
        extras = parse_extras(args.extra_slugs, args.wp_core)
        # A missing lock file is tolerated only when extras define what to check.
        lock_packages = load_packages(args.lock) if os.path.exists(args.lock) or not extras else []
        packages = _unique(lock_packages + extras)
        if not packages:
            raise ScanError("no WordPress packages found to check")
        if args.feed_file:
            try:
                with open(args.feed_file, encoding="utf-8") as handle:
                    feed = json.load(handle)
            except (OSError, ValueError) as exc:
                raise ScanError(f"cannot read feed file: {exc}") from exc
        else:
            api_key = os.environ.get("WORDFENCE_API_KEY", "").strip()
            if not api_key:
                raise ScanError("WORDFENCE_API_KEY is not set")
            feed = fetch_feed(api_key)
        findings, skipped = find_vulnerabilities(feed, packages)
    except ScanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    report = render_report(findings, packages, skipped, date)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as handle:
            handle.write(report)
    else:
        sys.stdout.write(report)
    if args.json_out:
        summary = {
            "date": date,
            "packages_checked": len(packages),
            "informational_skipped": skipped,
            "findings": findings,
        }
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump(summary, handle, indent=2, sort_keys=True)
            handle.write("\n")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
