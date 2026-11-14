"""headerguard - audit HTTP security headers, cookies and CORS."""

__version__ = "1.0.0"

from .checks import Finding, Report, analyze  # noqa: E402
from .fetch import FetchError, Response, fetch  # noqa: E402


def audit(url: str, **kwargs) -> Report:
    """Fetch `url` and return a graded security Report."""
    return analyze(fetch(url, **kwargs))


__all__ = ["Finding", "Report", "Response", "FetchError", "analyze", "audit", "fetch",
           "__version__"]
