"""End-to-end tests against a local HTTP server (no internet needed)."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from headerguard import audit, cli
from headerguard.fetch import FetchError, fetch


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(301)
            self.send_header("Location", "/hardened")
            self.end_headers()
            return
        if self.path == "/loop":
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.end_headers()
            return
        self.send_response(404 if self.path == "/missing" else 200)
        if self.path == "/hardened":
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; object-src 'none'; base-uri 'self'; "
                             "frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Permissions-Policy", "camera=()")
        if self.path == "/cors":
            self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Set-Cookie", "a=1; HttpOnly; SameSite=Lax")
        self.send_header("Set-Cookie", "b=2")
        self.end_headers()
        self.wfile.write(b"ok")


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def test_redirect_chain_and_multiple_cookies(server):
    resp = fetch(server + "/redirect")
    assert resp.status == 200
    assert resp.redirects == [(301, server + "/hardened")]
    assert len(resp.get_all("Set-Cookie")) == 2


def test_audit_detects_reflected_cors(server):
    report = audit(server + "/cors")
    cors = next(f for f in report.problems if f.id == "cors")
    assert cors.severity == "high"


def test_error_status_is_still_audited(server):
    assert audit(server + "/missing").status == 404


def test_redirect_loop_raises(server):
    with pytest.raises(FetchError):
        fetch(server + "/loop", max_redirects=3)


def test_cli_json_and_fail_under(server, capsys):
    code = cli.main([server + "/hardened", "--json", "--fail-under", "A"])
    data = json.loads(capsys.readouterr().out)
    assert data[0]["final_url"].endswith("/hardened")
    assert code == 1  # plain HTTP cannot reach grade A


def test_cli_text_output(server, capsys):
    assert cli.main([server + "/hardened", "--no-color", "-v"]) == 0
    out = capsys.readouterr().out
    assert "Site is not served over HTTPS" in out and "[  OK  ]" in out


def test_cli_unreachable_host(capsys):
    assert cli.main(["http://127.0.0.1:1/", "--timeout", "2"]) == 2
