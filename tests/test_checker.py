"""Integration tests for the URL checker using httpx mocks."""

from __future__ import annotations

import httpx
import pytest
import respx

from header_grade.checker import FetchError, check_url


@respx.mock
@pytest.mark.asyncio
async def test_full_check_good_site():
    """A site with all headers returns a high grade."""
    respx.get("https://example.com").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Content-Security-Policy": "default-src 'self'; object-src 'none'",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                "Cross-Origin-Opener-Policy": "same-origin",
                "Cross-Origin-Embedder-Policy": "require-corp",
                "Cross-Origin-Resource-Policy": "same-origin",
                "Origin-Agent-Cluster": "?1",
                "Reporting-Endpoints": 'default="https://example.com/reports"',
            },
        )
    )
    report = await check_url("https://example.com")
    assert report.score >= 80
    assert report.grade.value in {"A+", "A"}
    assert report.https is True


@respx.mock
@pytest.mark.asyncio
async def test_full_check_bad_site():
    """A site with no headers gets a very low grade."""
    respx.get("https://bad.example.com").mock(
        return_value=httpx.Response(200, headers={})
    )
    report = await check_url("https://bad.example.com")
    assert report.score < 30
    assert report.grade.value == "F"


@respx.mock
@pytest.mark.asyncio
async def test_url_normalisation():
    """Missing scheme is filled in as https://."""
    respx.get("https://example.com").mock(
        return_value=httpx.Response(200, headers={"X-Content-Type-Options": "nosniff"})
    )
    report = await check_url("example.com")
    assert report.url == "https://example.com"


@pytest.mark.asyncio
async def test_invalid_url_raises():
    # A URL with no host after stripping the path component raises FetchError
    with pytest.raises(FetchError):
        await check_url("https:///no-host-here")


@respx.mock
@pytest.mark.asyncio
async def test_server_header_captured():
    respx.get("https://example.com").mock(
        return_value=httpx.Response(200, headers={"Server": "nginx/1.24"})
    )
    report = await check_url("https://example.com")
    assert report.server == "nginx/1.24"


@respx.mock
@pytest.mark.asyncio
async def test_redirect_chain_captured():
    # Mock both the initial and redirect target URLs
    respx.get("https://example.com").mock(
        return_value=httpx.Response(301, headers={"Location": "https://www.example.com/"})
    )
    respx.get("https://www.example.com/").mock(
        return_value=httpx.Response(200, headers={})
    )
    report = await check_url("https://example.com")
    assert isinstance(report.redirect_chain, list)
    # At least one redirect was followed
    assert len(report.redirect_chain) >= 1
