"""Command line interface: `headerguard URL [URL ...]`."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, List, Optional

from . import __version__
from .checks import GRADES, Report, analyze, grade_rank
from .fetch import FetchError, fetch

COLORS = {"high": "31", "medium": "33", "low": "36", "info": "37", "ok": "32"}
GRADE_COLORS = {"A+": "32", "A": "32", "B": "33", "C": "33", "D": "31", "F": "31"}


def _paint(text: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


def format_report(report: Report, color: bool, verbose: bool) -> str:
    lines = []
    grade = _paint(f"{report.grade} ({report.score}/100)",
                   "1;" + GRADE_COLORS[report.grade], color)
    lines.append(f"{report.url}  ->  grade {grade}")
    if report.final_url != report.url:
        lines.append(f"  final URL: {report.final_url} (HTTP {report.status})")
    if report.status >= 400:
        lines.append(_paint(f"  warning: HTTP {report.status} - error pages often carry "
                            "different headers than real pages", COLORS["medium"], color))
    for f in report.problems:
        tag = _paint(f"[{f.severity.upper():<6}]", COLORS[f.severity], color)
        lines.append(f"  {tag} {f.title}  (-{f.penalty})")
        if f.detail:
            lines.append(f"           {f.detail}")
        if f.fix:
            lines.append(f"           fix: {f.fix}")
    if verbose:
        for f in report.findings:
            if f.passed:
                lines.append(f"  {_paint('[  OK  ]', COLORS['ok'], color)} {f.title}"
                             + (f"  ({f.detail})" if f.detail else ""))
    if not report.problems:
        lines.append("  no issues found")
    return "\n".join(lines)


def _parse_headers(values: List[str]) -> Dict[str, str]:
    headers = {}
    for item in values:
        if ":" not in item:
            raise SystemExit(f"headerguard: invalid header '{item}', expected 'Name: value'")
        name, value = item.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="headerguard",
        description="Audit HTTP security headers, cookies and CORS of a website "
                    "and grade it from A+ to F.",
    )
    parser.add_argument("urls", nargs="+", help="URLs to audit (https:// is assumed)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--fail-under", metavar="GRADE", choices=[g for g, _ in GRADES],
                        help="exit with code 1 if any grade is worse than GRADE (for CI)")
    parser.add_argument("-H", "--header", action="append", default=[],
                        help="extra request header, e.g. -H 'Cookie: session=...'")
    parser.add_argument("--timeout", type=float, default=10.0, help="seconds (default 10)")
    parser.add_argument("-k", "--insecure", action="store_true",
                        help="do not verify TLS certificates")
    parser.add_argument("--no-redirects", action="store_true", help="do not follow redirects")
    parser.add_argument("-v", "--verbose", action="store_true", help="also list passed checks")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    extra = _parse_headers(args.header)
    color = (not args.no_color and not args.json and sys.stdout.isatty()
             and os.environ.get("NO_COLOR") is None)

    exit_code = 0
    reports = []
    for url in args.urls:
        try:
            response = fetch(url, timeout=args.timeout, insecure=args.insecure,
                             follow_redirects=not args.no_redirects, extra_headers=extra)
        except FetchError as err:
            print(f"headerguard: {err}", file=sys.stderr)
            exit_code = 2
            continue
        report = analyze(response)
        reports.append(report)
        if args.fail_under and grade_rank(report.grade) > grade_rank(args.fail_under):
            exit_code = max(exit_code, 1)
        if not args.json:
            print(format_report(report, color, args.verbose))
            print()

    if args.json:
        print(json.dumps([r.to_dict() for r in reports], indent=2))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
