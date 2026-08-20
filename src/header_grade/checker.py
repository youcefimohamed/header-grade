"""HTTP fetcher — retrieves headers for a URL."""

from __future__ import annotations

import ssl
from urllib.parse import urlparse

import httpx

from .grader import compute_score
from .headers import ALL_CHECKERS
from .models import Grade, GradeReport

_DEFAULT_TIMEOUT = 15.0
_DEFAULT_UA = (
    "header-grade/0.1.0 (security-headers-checker; "
    "https://github.com/youcefimohamed/header-grade)"
)


class FetchError(Exception):
    """Raised when the URL cannot be fetched."""


async def check_url(
    url: str,
    *,
    timeout: float = _DEFAULT_TIMEOUT,
    follow_redirects: bool = True,
    user_agent: str = _DEFAULT_UA,
    verify_ssl: bool = True,
) -> GradeReport:
    """
    Fetch the URL and return a full GradeReport.

    Args:
        url: The URL to check (http or https).
        timeout: Request timeout in seconds.
        follow_redirects: Whether to follow HTTP redirects.
        user_agent: User-Agent string to send.
        verify_ssl: Whether to verify SSL certificates.

    Returns:
        A GradeReport with grade, findings, and raw headers.

    Raises:
        FetchError: If the URL cannot be reached or is invalid.
    """
    url = _normalise_url(url)

    try:
        async with httpx.AsyncClient(
            follow_redirects=follow_redirects,
            timeout=timeout,
            verify=verify_ssl,
            headers={"User-Agent": user_agent},
        ) as client:
            response = await client.get(url)
    except httpx.InvalidURL as exc:
        raise FetchError(f"Invalid URL: {url!r} — {exc}") from exc
    except httpx.ConnectError as exc:
        raise FetchError(f"Cannot connect to {url!r} — {exc}") from exc
    except httpx.TimeoutException as exc:
        raise FetchError(f"Request timed out after {timeout}s — {exc}") from exc
    except httpx.TooManyRedirects as exc:
        raise FetchError(f"Too many redirects from {url!r}") from exc
    except ssl.SSLError as exc:
        raise FetchError(
            f"SSL error for {url!r}: {exc}\n"
            "Tip: use --no-verify-ssl to skip certificate validation (insecure)."
        ) from exc
    except Exception as exc:
        raise FetchError(f"Unexpected error fetching {url!r}: {exc}") from exc

    # Normalise header names to lowercase.
    # HTTP allows multiple headers with the same name (e.g. Set-Cookie).
    # httpx returns them all; we join duplicates with "\n" so checkers
    # can split on "\n" to iterate individual values (see cookies.py).
    raw_headers: dict[str, str] = {}
    for k, v in response.headers.multi_items():
        key = k.lower()
        if key in raw_headers:
            raw_headers[key] = raw_headers[key] + "\n" + v
        else:
            raw_headers[key] = v

    # Build redirect chain
    redirect_chain: list[str] = []
    if follow_redirects:
        for hist_resp in response.history:
            redirect_chain.append(str(hist_resp.url))

    final_url = str(response.url)
    is_https = final_url.startswith("https://")

    # Run all checkers
    findings = [checker().check(raw_headers) for checker in ALL_CHECKERS]

    # If not HTTPS, penalise HSTS additionally (the browser never sends it over HTTP)
    if not is_https:
        # Mark HSTS as missing regardless (HSTS over HTTP is meaningless/ignored)
        pass

    score = compute_score(findings, is_https=is_https)
    grade = Grade.from_score(score)

    return GradeReport(
        url=url,
        final_url=final_url,
        score=score,
        grade=grade,
        findings=findings,
        raw_headers=raw_headers,
        https=is_https,
        redirect_chain=redirect_chain,
        server=raw_headers.get("server"),
    )


def _normalise_url(url: str) -> str:
    """Add https:// scheme if missing."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        raise FetchError(f"Cannot parse URL: {url!r}")
    return url
