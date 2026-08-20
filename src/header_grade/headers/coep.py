"""Cross-Origin-Embedder-Policy (COEP) checker."""

from __future__ import annotations

from ..models import FindingStatus, HeaderFinding, Severity
from .base import BaseHeaderChecker

_STRONG_VALUES = {"require-corp", "credentialless"}
_VALID_VALUES = _STRONG_VALUES | {"unsafe-none"}


class COEPChecker(BaseHeaderChecker):
    """
    COEP ensures every cross-origin resource your page loads has explicitly
    opted in to being embedded, enabling cross-origin isolation.
    """

    header_name = "cross-origin-embedder-policy"
    max_penalty = 5
    bonus = 0

    def check(self, headers: dict[str, str]) -> HeaderFinding:
        value = self._get(headers)

        if value is None:
            return HeaderFinding(
                header="Cross-Origin-Embedder-Policy",
                status=FindingStatus.MISSING,
                severity=Severity.LOW,
                score_impact=-self.max_penalty,
                title="Cross-Origin-Embedder-Policy (COEP) is missing",
                description=(
                    "COEP requires all cross-origin resources loaded by your page to "
                    "opt in via CORS or CORP. Together with COOP, it enables "
                    "cross-origin isolation — a prerequisite for SharedArrayBuffer and "
                    "Spectre mitigations."
                ),
                recommendation=(
                    "If you control all embedded resources:\n\n"
                    "  Cross-Origin-Embedder-Policy: require-corp\n\n"
                    "If you embed third-party resources without CORP:\n\n"
                    "  Cross-Origin-Embedder-Policy: credentialless"
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy",
                    "https://web.dev/coop-coep/",
                ],
                exploit_scenario=(
                    "Spectre-class side-channel via cross-origin isolation bypass:\n\n"
                    "Without COEP+COOP together, cross-origin isolation is not active.\n"
                    "An attacker can:\n\n"
                    "1. Embed your authenticated page in an iframe on evil.com\n"
                    "2. Use SharedArrayBuffer + Atomics.wait() as a precise timer\n"
                    "3. Prime and probe CPU cache lines to detect which memory addresses\n"
                    "   the browser accessed while rendering your cross-origin content\n"
                    "4. Infer pixel values of cross-origin iframes → pixel-stealing\n"
                    "5. Reconstruct secrets visible in the rendered page content\n\n"
                    "This is the browser-level variant of the Spectre CPU vulnerability.\n"
                    "Chrome disabled SharedArrayBuffer for non-isolated origins in 2021\n"
                    "to prevent this — but COEP is required to re-enable safe usage."
                ),
                exploit_references=[
                    "https://xsleaks.dev/",
                    "https://web.dev/coop-coep/",
                    "https://developer.chrome.com/blog/enabling-shared-array-buffer/",
                    "https://spectreattack.com/",
                    "https://arxiv.org/abs/2103.04952",
                ],
            )

        normalized = value.strip().lower()
        if normalized not in _VALID_VALUES:
            return HeaderFinding(
                header="Cross-Origin-Embedder-Policy",
                status=FindingStatus.INVALID,
                severity=Severity.LOW,
                score_impact=-3,
                title=f"COEP has an unrecognised value: '{value}'",
                description="The value is not a valid COEP token.",
                current_value=value,
                recommendation="Use 'require-corp' or 'credentialless'.",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy"
                ],
            )

        if normalized == "unsafe-none":
            return HeaderFinding(
                header="Cross-Origin-Embedder-Policy",
                status=FindingStatus.WARNING,
                severity=Severity.LOW,
                score_impact=-3,
                title="COEP is 'unsafe-none' — no cross-origin isolation",
                description="'unsafe-none' is the default and provides no protection.",
                current_value=value,
                recommendation="Change to 'require-corp' or 'credentialless'.",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy"
                ],
            )

        return HeaderFinding(
            header="Cross-Origin-Embedder-Policy",
            status=FindingStatus.PRESENT,
            severity=Severity.LOW,
            score_impact=0,
            title=f"Cross-Origin-Embedder-Policy: {normalized}",
            description=(
                "COEP is active — cross-origin resources must opt in to be loaded, "
                "enabling cross-origin isolation."
            ),
            current_value=value,
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy"
            ],
        )
