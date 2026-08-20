"""Origin-Agent-Cluster checker — process isolation for XS-Leak mitigation."""

from __future__ import annotations

from ..models import FindingStatus, HeaderFinding, Severity
from .base import BaseHeaderChecker


class OriginAgentClusterChecker(BaseHeaderChecker):
    """
    Origin-Agent-Cluster: ?1 opts the document into a separate OS process
    (or agent cluster) per origin, rather than per site.

    Without it, a site-keyed cluster means same-site subdomains share a process,
    making Spectre-class cross-subdomain attacks easier.

    This is an informational/advisory check — the header is new (Chrome 88+)
    and not universally supported, so absence is a minor advisory, not a critical issue.
    """

    header_name = "origin-agent-cluster"
    max_penalty = 3
    bonus = 0

    def check(self, headers: dict[str, str]) -> HeaderFinding:
        value = self._get(headers)

        if value is None:
            return HeaderFinding(
                header="Origin-Agent-Cluster",
                status=FindingStatus.MISSING,
                severity=Severity.LOW,
                score_impact=-self.max_penalty,
                title="Origin-Agent-Cluster is not set (process isolation advisory)",
                description=(
                    "Origin-Agent-Cluster: ?1 opts the document into a separate agent cluster "
                    "per origin, instead of the default per-site clustering. This means even "
                    "same-site subdomains get separate OS processes in supporting browsers "
                    "(Chrome 88+, Edge 88+). Without it, a compromised or malicious subdomain "
                    "shares your origin's process memory — making Spectre-class cross-origin "
                    "reads slightly easier. This is advisory — absence is not catastrophic, "
                    "but adding it is a one-line win."
                ),
                recommendation=(
                    "Add to your server response headers:\n\n"
                    "  Origin-Agent-Cluster: ?1\n\n"
                    "This is a structured header using the '?1' boolean token syntax."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin-Agent-Cluster",
                    "https://web.dev/origin-agent-cluster/",
                    "https://xsleaks.dev/",
                ],
                exploit_scenario=(
                    "Without origin-keyed agent clusters, browsers may place:\n"
                    "  app.example.com (your app)\n"
                    "  blog.example.com (a WordPress subdomain)\n"
                    "  uploads.example.com (user-uploaded content)\n"
                    "...all in the same OS process.\n\n"
                    "If an attacker compromises uploads.example.com (e.g. stored XSS in uploads),\n"
                    "they are in the same process as app.example.com. Using Spectre-class\n"
                    "cache-timing attacks, they can potentially read cross-origin memory from\n"
                    "the app.example.com document in the same process.\n\n"
                    "Origin-Agent-Cluster: ?1 signals to the browser to give each origin\n"
                    "its own process — the compromised subdomain can no longer read the app's memory."
                ),
                exploit_references=[
                    "https://xsleaks.dev/",
                    "https://web.dev/origin-agent-cluster/",
                    "https://spectreattack.com/",
                    "https://developer.chrome.com/blog/origin-isolation/",
                ],
            )

        normalized = value.strip().lower()

        if normalized in {"?1", "?0"}:
            enabled = normalized == "?1"
            return HeaderFinding(
                header="Origin-Agent-Cluster",
                status=FindingStatus.PRESENT if enabled else FindingStatus.WARNING,
                severity=Severity.LOW,
                score_impact=0 if enabled else -2,
                title=f"Origin-Agent-Cluster: {normalized}"
                + (" (process isolation enabled)" if enabled else " (isolation disabled)"),
                description=(
                    "Origin-Agent-Cluster is set to ?1 — the origin gets its own agent cluster "
                    "(process) in supporting browsers, improving isolation against XS-Leaks."
                    if enabled
                    else
                    "Origin-Agent-Cluster: ?0 explicitly opts OUT of origin-keyed clustering. "
                    "This is the default behaviour — consider changing to ?1 for better isolation."
                ),
                current_value=value,
                recommendation=None if enabled else "Change to: Origin-Agent-Cluster: ?1",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin-Agent-Cluster",
                    "https://web.dev/origin-agent-cluster/",
                ],
            )

        return HeaderFinding(
            header="Origin-Agent-Cluster",
            status=FindingStatus.INVALID,
            severity=Severity.LOW,
            score_impact=-2,
            title=f"Origin-Agent-Cluster has an unexpected value: '{value}'",
            description=(
                "Origin-Agent-Cluster uses structured boolean header syntax. "
                "'?1' enables isolation, '?0' disables it."
            ),
            current_value=value,
            recommendation="Set to: Origin-Agent-Cluster: ?1",
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin-Agent-Cluster"
            ],
        )
