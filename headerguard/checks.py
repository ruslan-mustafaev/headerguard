"""Security checks over an HTTP response. Pure functions, no network access."""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import asdict, dataclass, field
from typing import Dict, List

from .fetch import PROBE_ORIGIN, Response

SEVERITIES = ("high", "medium", "low", "info")
GRADES = (("A+", 95), ("A", 85), ("B", 70), ("C", 55), ("D", 40), ("F", 0))
HSTS_MIN_AGE = 15552000          # 180 days
COOKIE_PENALTY_CAP = 15


@dataclass
class Finding:
    id: str
    title: str
    passed: bool
    severity: str = "info"       # only meaningful when passed is False
    penalty: int = 0
    detail: str = ""
    fix: str = ""


@dataclass
class Report:
    url: str
    final_url: str
    status: int
    findings: List[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        return max(0, 100 - sum(f.penalty for f in self.findings if not f.passed))

    @property
    def grade(self) -> str:
        for grade, minimum in GRADES:
            if self.score >= minimum:
                return grade
        return "F"

    @property
    def problems(self) -> List[Finding]:
        order = {s: i for i, s in enumerate(SEVERITIES)}
        return sorted((f for f in self.findings if not f.passed),
                      key=lambda f: (order[f.severity], -f.penalty))

    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status": self.status,
            "score": self.score,
            "grade": self.grade,
            "findings": [asdict(f) for f in self.findings],
        }


def grade_rank(grade: str) -> int:
    """Lower is better: A+ -> 0, F -> 5."""
    return [g for g, _ in GRADES].index(grade)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_csp(value: str) -> Dict[str, List[str]]:
    directives: Dict[str, List[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            name = tokens[0].lower()
            directives.setdefault(name, [t for t in tokens[1:]])
    return directives


def _ok(id_: str, title: str, detail: str = "") -> Finding:
    return Finding(id_, title, True, detail=detail)


def _bad(id_: str, title: str, severity: str, penalty: int, detail: str, fix: str) -> Finding:
    return Finding(id_, title, False, severity, penalty, detail, fix)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_https(resp: Response) -> List[Finding]:
    final_scheme = urllib.parse.urlsplit(resp.url).scheme
    requested_scheme = urllib.parse.urlsplit(resp.requested_url or resp.url).scheme
    if final_scheme != "https":
        return [_bad("https", "Site is not served over HTTPS", "high", 30,
                     f"Final URL is {resp.url}",
                     "Serve the site over HTTPS and redirect all HTTP traffic to it.")]
    if requested_scheme == "http":
        return [_ok("https", "HTTP redirects to HTTPS")]
    return [_ok("https", "Served over HTTPS")]


def check_hsts(resp: Response) -> List[Finding]:
    if urllib.parse.urlsplit(resp.url).scheme != "https":
        return []
    value = resp.get("Strict-Transport-Security")
    if not value:
        return [_bad("hsts", "Strict-Transport-Security missing", "high", 20, "",
                     "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains")]
    match = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.I)
    age = int(match.group(1)) if match else 0
    findings = []
    if age < HSTS_MIN_AGE:
        findings.append(_bad("hsts-max-age", "HSTS max-age is too short", "medium", 5,
                             f"max-age={age}", "Use max-age of at least 15552000 (180 days)."))
    else:
        findings.append(_ok("hsts", "Strict-Transport-Security enabled", f"max-age={age}"))
    if "includesubdomains" not in value.lower():
        findings.append(_bad("hsts-subdomains", "HSTS does not include subdomains", "low", 2,
                             value, "Add includeSubDomains once all subdomains support HTTPS."))
    return findings


def check_csp(resp: Response) -> List[Finding]:
    value = resp.get("Content-Security-Policy")
    if not value:
        if resp.get("Content-Security-Policy-Report-Only"):
            return [_bad("csp", "CSP is only in Report-Only mode", "medium", 12,
                         "Content-Security-Policy-Report-Only does not block anything.",
                         "Enforce the policy with the Content-Security-Policy header.")]
        return [_bad("csp", "Content-Security-Policy missing", "high", 20, "",
                     "Start with: default-src 'self'; object-src 'none'; base-uri 'self'; "
                     "frame-ancestors 'self'")]

    csp = parse_csp(value)
    script = csp.get("script-src", csp.get("default-src"))
    findings = [_ok("csp", "Content-Security-Policy present")]
    if script is None:
        findings.append(_bad("csp-script-src", "CSP does not restrict scripts", "medium", 10,
                             "Neither script-src nor default-src is set.",
                             "Add default-src 'self' or an explicit script-src."))
    else:
        lowered = [s.lower() for s in script]
        has_nonce_or_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
                                for s in lowered)
        strict = "'strict-dynamic'" in lowered
        if "'unsafe-inline'" in lowered and not has_nonce_or_hash:
            findings.append(_bad("csp-unsafe-inline", "CSP allows 'unsafe-inline' scripts",
                                 "medium", 10, " ".join(script),
                                 "Replace 'unsafe-inline' with nonces or hashes."))
        if "'unsafe-eval'" in lowered:
            findings.append(_bad("csp-unsafe-eval", "CSP allows 'unsafe-eval'", "low", 5,
                                 " ".join(script), "Remove 'unsafe-eval' (avoid eval/new Function)."))
        wide = [s for s in lowered if s in ("*", "http:", "https:", "data:")]
        if wide and not strict:
            findings.append(_bad("csp-wildcard", "CSP allows scripts from any host", "medium", 10,
                                 "Sources: " + " ".join(wide),
                                 "List explicit hosts or use nonces with 'strict-dynamic'."))
    default_none = csp.get("default-src") == ["'none'"]
    if "object-src" not in csp and not default_none:
        findings.append(_bad("csp-object-src", "CSP does not set object-src", "low", 3, "",
                             "Add object-src 'none'."))
    if "base-uri" not in csp:
        findings.append(_bad("csp-base-uri", "CSP does not set base-uri", "low", 2, "",
                             "Add base-uri 'self' (or 'none')."))
    return findings


def check_clickjacking(resp: Response) -> List[Finding]:
    csp = parse_csp(resp.get("Content-Security-Policy") or "")
    if "frame-ancestors" in csp:
        return [_ok("clickjacking", "Framing restricted by CSP frame-ancestors",
                    " ".join(csp["frame-ancestors"]))]
    xfo = (resp.get("X-Frame-Options") or "").strip().upper()
    if xfo in ("DENY", "SAMEORIGIN"):
        return [_ok("clickjacking", "Framing restricted by X-Frame-Options", xfo)]
    detail = f"X-Frame-Options: {xfo}" if xfo else "No X-Frame-Options or frame-ancestors"
    return [_bad("clickjacking", "Page can be framed (clickjacking)", "medium", 10, detail,
                 "Add CSP frame-ancestors 'self' (and X-Frame-Options: SAMEORIGIN for old browsers).")]


def check_nosniff(resp: Response) -> List[Finding]:
    if (resp.get("X-Content-Type-Options") or "").strip().lower() == "nosniff":
        return [_ok("nosniff", "X-Content-Type-Options: nosniff")]
    return [_bad("nosniff", "X-Content-Type-Options missing", "medium", 5, "",
                 "Add: X-Content-Type-Options: nosniff")]


def check_referrer(resp: Response) -> List[Finding]:
    value = (resp.get("Referrer-Policy") or "").strip().lower()
    if not value:
        return [_bad("referrer", "Referrer-Policy missing", "low", 3, "",
                     "Add: Referrer-Policy: strict-origin-when-cross-origin")]
    last = value.split(",")[-1].strip()   # browsers use the last supported value
    if last in ("unsafe-url", "no-referrer-when-downgrade"):
        return [_bad("referrer", "Referrer-Policy leaks full URLs", "low", 5, value,
                     "Use strict-origin-when-cross-origin or no-referrer.")]
    return [_ok("referrer", "Referrer-Policy set", value)]


def check_permissions_policy(resp: Response) -> List[Finding]:
    if resp.get("Permissions-Policy"):
        return [_ok("permissions", "Permissions-Policy set")]
    return [_bad("permissions", "Permissions-Policy missing", "low", 2, "",
                 "Disable unused features, e.g. Permissions-Policy: camera=(), microphone=(), "
                 "geolocation=()")]


def check_info_leaks(resp: Response) -> List[Finding]:
    findings = []
    server = resp.get("Server") or ""
    if re.search(r"\d+\.\d+", server):
        findings.append(_bad("server-version", "Server header discloses version", "low", 2,
                             f"Server: {server}", "Hide version numbers (e.g. server_tokens off)."))
    for header in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
        value = resp.get(header)
        if value:
            findings.append(_bad("powered-by", f"{header} discloses technology", "low", 3,
                                 f"{header}: {value}", f"Remove the {header} header."))
    if not findings:
        findings.append(_ok("info-leak", "No technology/version disclosure in headers"))
    return findings


def check_cookies(resp: Response) -> List[Finding]:
    cookies = resp.get_all("Set-Cookie")
    if not cookies:
        return []
    https = urllib.parse.urlsplit(resp.url).scheme == "https"
    findings: List[Finding] = []
    for raw in cookies:
        name = raw.split("=", 1)[0].strip()
        attrs = [a.strip().lower() for a in raw.split(";")[1:]]
        keys = {a.split("=", 1)[0] for a in attrs}
        samesite = next((a.split("=", 1)[1] for a in attrs
                         if a.startswith("samesite=")), None)
        problems = []
        penalty = 0
        if "secure" not in keys and (https or samesite == "none"):
            problems.append("no Secure")
            penalty += 5
        if "httponly" not in keys:
            problems.append("no HttpOnly")
            penalty += 3
        if samesite is None:
            problems.append("no SameSite")
            penalty += 2
        if problems:
            findings.append(_bad("cookie", f"Cookie '{name}' is missing flags", "medium"
                                 if "no Secure" in problems else "low", penalty,
                                 ", ".join(problems),
                                 "Set cookies with Secure; HttpOnly; SameSite=Lax (or Strict)."))
        else:
            findings.append(_ok("cookie", f"Cookie '{name}' has Secure, HttpOnly, SameSite"))

    # Cap the total cookie penalty so many cookies do not dominate the score.
    total = 0
    for f in findings:
        if not f.passed:
            f.penalty = max(0, min(f.penalty, COOKIE_PENALTY_CAP - total))
            total += f.penalty
    return findings


def check_cors(resp: Response) -> List[Finding]:
    acao = (resp.get("Access-Control-Allow-Origin") or "").strip()
    if not acao:
        return []
    credentials = (resp.get("Access-Control-Allow-Credentials") or "").strip().lower() == "true"
    if acao == PROBE_ORIGIN:
        if credentials:
            return [_bad("cors", "CORS reflects any Origin with credentials", "high", 25,
                         f"Access-Control-Allow-Origin: {acao}; Allow-Credentials: true",
                         "Allow only a fixed list of trusted origins.")]
        return [_bad("cors", "CORS reflects any Origin", "medium", 10,
                     f"Access-Control-Allow-Origin: {acao}",
                     "Allow only a fixed list of trusted origins.")]
    if acao == "*" and credentials:
        return [_bad("cors", "CORS wildcard combined with credentials", "medium", 8,
                     "Access-Control-Allow-Origin: * with Allow-Credentials: true",
                     "Never combine * with credentials; list explicit origins.")]
    if acao == "null":
        return [_bad("cors", "CORS allows the 'null' origin", "medium", 8, "",
                     "Do not allow the null origin (sandboxed iframes can use it).")]
    return [_ok("cors", "CORS policy is not reflective", f"Access-Control-Allow-Origin: {acao}")]


ALL_CHECKS = (
    check_https, check_hsts, check_csp, check_clickjacking, check_nosniff,
    check_referrer, check_permissions_policy, check_info_leaks, check_cookies, check_cors,
)


def analyze(resp: Response) -> Report:
    report = Report(url=resp.requested_url or resp.url, final_url=resp.url, status=resp.status)
    for check in ALL_CHECKS:
        report.findings.extend(check(resp))
    return report
