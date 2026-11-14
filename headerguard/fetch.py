"""HTTP fetching with an explicit redirect chain (stdlib only)."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

USER_AGENT = "headerguard/1.0 (+https://github.com/ruslan-mustafaev/headerguard)"

# A unique, non-resolvable origin used to detect CORS origin reflection.
PROBE_ORIGIN = "https://headerguard-probe.invalid"


@dataclass
class Response:
    url: str                                   # final URL after redirects
    status: int
    headers: List[Tuple[str, str]]             # raw headers, order preserved
    redirects: List[Tuple[int, str]] = field(default_factory=list)  # (status, location)
    requested_url: str = ""

    def get(self, name: str) -> Optional[str]:
        """Return the first header value (case-insensitive) or None."""
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return None

    def get_all(self, name: str) -> List[str]:
        name = name.lower()
        return [value for key, value in self.headers if key.lower() == name]

    @property
    def header_dict(self) -> Dict[str, str]:
        result: Dict[str, str] = {}
        for key, value in self.headers:
            result.setdefault(key.lower(), value)
        return result


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


class FetchError(Exception):
    pass


def normalize_url(url: str) -> str:
    if "://" not in url:
        url = "https://" + url
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise FetchError(f"unsupported URL: {url}")
    return url


def fetch(url: str, timeout: float = 10.0, insecure: bool = False,
          follow_redirects: bool = True, max_redirects: int = 10,
          extra_headers: Optional[Dict[str, str]] = None) -> Response:
    url = normalize_url(url)
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        _NoRedirect(), urllib.request.HTTPSHandler(context=context))

    headers = {"User-Agent": USER_AGENT, "Origin": PROBE_ORIGIN, "Accept": "*/*"}
    headers.update(extra_headers or {})

    requested = url
    redirects: List[Tuple[int, str]] = []
    for _ in range(max_redirects + 1):
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            raw = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as err:   # 3xx/4xx/5xx still carry headers
            raw = err
        except (urllib.error.URLError, OSError) as err:
            reason = getattr(err, "reason", err)
            raise FetchError(f"{url}: {reason}") from err

        status = raw.status if hasattr(raw, "status") else raw.code
        header_items = list(raw.headers.items())
        raw.close()

        location = raw.headers.get("Location")
        if follow_redirects and 300 <= status < 400 and location:
            next_url = urllib.parse.urljoin(url, location)
            redirects.append((status, next_url))
            url = next_url
            continue
        return Response(url=url, status=status, headers=header_items,
                        redirects=redirects, requested_url=requested)
    raise FetchError(f"{requested}: more than {max_redirects} redirects")
