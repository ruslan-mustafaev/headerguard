from headerguard.checks import analyze, grade_rank, parse_csp
from headerguard.fetch import PROBE_ORIGIN, Response

GOOD_HEADERS = [
    ("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"),
    ("Content-Security-Policy",
     "default-src 'self'; script-src 'self' 'nonce-abc'; object-src 'none'; "
     "base-uri 'self'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "camera=(), microphone=()"),
    ("Set-Cookie", "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"),
]


def make(headers, url="https://example.com/", requested=None, status=200):
    return Response(url=url, status=status, headers=list(headers),
                    requested_url=requested or url)


def ids(report):
    return {f.id for f in report.problems}


def test_hardened_site_gets_a_plus():
    report = analyze(make(GOOD_HEADERS))
    assert report.problems == []
    assert report.score == 100 and report.grade == "A+"


def test_bare_site_gets_f():
    report = analyze(make([("Server", "nginx/1.18.0"), ("X-Powered-By", "PHP/8.1")]))
    assert {"hsts", "csp", "clickjacking", "nosniff", "referrer", "permissions",
            "server-version", "powered-by"} <= ids(report)
    assert report.grade == "F"


def test_plain_http_is_high_severity():
    report = analyze(make([], url="http://example.com/"))
    https = next(f for f in report.findings if f.id == "https")
    assert not https.passed and https.severity == "high"
    assert "hsts" not in ids(report)  # HSTS is meaningless over HTTP


def test_http_to_https_redirect_passes():
    report = analyze(make(GOOD_HEADERS, requested="http://example.com/"))
    https = next(f for f in report.findings if f.id == "https")
    assert https.passed and "redirects" in https.title


def test_short_hsts():
    headers = [h for h in GOOD_HEADERS if h[0] != "Strict-Transport-Security"]
    headers.append(("Strict-Transport-Security", "max-age=300"))
    assert {"hsts-max-age", "hsts-subdomains"} <= ids(analyze(make(headers)))


def test_csp_unsafe_inline_without_nonce():
    headers = [h for h in GOOD_HEADERS if h[0] != "Content-Security-Policy"]
    headers.append(("Content-Security-Policy",
                    "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:"))
    problems = ids(analyze(make(headers)))
    assert {"csp-unsafe-inline", "csp-unsafe-eval", "csp-wildcard",
            "csp-object-src", "csp-base-uri", "clickjacking"} <= problems


def test_unsafe_inline_ignored_when_nonce_present():
    headers = [h for h in GOOD_HEADERS if h[0] != "Content-Security-Policy"]
    headers.append(("Content-Security-Policy",
                    "script-src 'nonce-xyz' 'unsafe-inline' 'strict-dynamic' https:; "
                    "object-src 'none'; base-uri 'none'; frame-ancestors 'self'"))
    problems = ids(analyze(make(headers)))
    assert "csp-unsafe-inline" not in problems and "csp-wildcard" not in problems


def test_report_only_csp():
    headers = [h for h in GOOD_HEADERS if h[0] != "Content-Security-Policy"]
    headers += [("Content-Security-Policy-Report-Only", "default-src 'self'"),
                ("X-Frame-Options", "DENY")]
    report = analyze(make(headers))
    csp = next(f for f in report.problems if f.id == "csp")
    assert csp.severity == "medium"
    assert "clickjacking" not in ids(report)


def test_cookie_flags_and_cap():
    headers = [h for h in GOOD_HEADERS if h[0] != "Set-Cookie"]
    headers += [("Set-Cookie", f"c{i}=1; Path=/") for i in range(10)]
    report = analyze(make(headers))
    cookie_penalty = sum(f.penalty for f in report.problems if f.id == "cookie")
    assert cookie_penalty == 15


def test_cors_reflection_with_credentials():
    headers = GOOD_HEADERS + [("Access-Control-Allow-Origin", PROBE_ORIGIN),
                              ("Access-Control-Allow-Credentials", "true")]
    cors = next(f for f in analyze(make(headers)).problems if f.id == "cors")
    assert cors.severity == "high"


def test_cors_static_origin_is_fine():
    headers = GOOD_HEADERS + [("Access-Control-Allow-Origin", "https://app.example.com")]
    assert "cors" not in ids(analyze(make(headers)))


def test_referrer_policy_last_value_wins():
    headers = [h for h in GOOD_HEADERS if h[0] != "Referrer-Policy"]
    headers.append(("Referrer-Policy", "no-referrer, unsafe-url"))
    assert "referrer" in ids(analyze(make(headers)))


def test_parse_csp_and_grade_rank():
    csp = parse_csp("default-src 'self'; img-src * data:;; ")
    assert csp == {"default-src": ["'self'"], "img-src": ["*", "data:"]}
    assert grade_rank("A+") < grade_rank("B") < grade_rank("F")
