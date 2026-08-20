"""Terminal and JSON reporters for GradeReport."""

from __future__ import annotations

import json
from typing import Any

from rich import box
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ._console import make_console
from .models import FindingStatus, Grade, GradeReport, Severity

console = make_console()

# ── grade colour mapping ──────────────────────────────────────────────────────

_GRADE_COLOUR: dict[str, str] = {
    "A+": "bright_green",
    "A":  "green",
    "B":  "yellow",
    "C":  "dark_orange",
    "D":  "red",
    "E":  "bright_red",
    "F":  "bold bright_red",
}

_STATUS_ICON: dict[FindingStatus, str] = {
    FindingStatus.PRESENT: "+",
    FindingStatus.WARNING: "!",
    FindingStatus.MISSING: "x",
    FindingStatus.INVALID: "x",
}

_STATUS_COLOUR: dict[FindingStatus, str] = {
    FindingStatus.PRESENT: "green",
    FindingStatus.WARNING: "yellow",
    FindingStatus.MISSING: "red",
    FindingStatus.INVALID: "red",
}

_SEVERITY_COLOUR: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "red",
    Severity.MEDIUM:   "dark_orange",
    Severity.LOW:      "yellow",
    Severity.INFO:     "dim",
}


# ── public API ────────────────────────────────────────────────────────────────

def print_report(report: GradeReport, *, verbose: bool = False) -> None:
    """Print a human-friendly report to the terminal."""
    _print_header(report)
    _print_findings_table(report)
    if verbose:
        _print_detailed_findings(report)
    _print_summary(report)


def print_json(report: GradeReport) -> None:
    """Print the report as JSON (for pipeline consumption)."""
    console.print_json(json.dumps(_to_dict(report), indent=2))


def print_github(report: GradeReport) -> None:
    """
    Print GitHub Actions workflow command annotations.

    Outputs ::error:: / ::warning:: / ::notice:: lines that GitHub Actions
    renders as inline PR annotations in the Actions log and (with SARIF upload)
    in the Security tab.

    Usage in a workflow step:
        - run: hg check ${{ env.DEPLOY_URL }} --format github
    """
    import sys

    _level_map = {
        "critical": "error",
        "high":     "error",
        "medium":   "warning",
        "low":      "notice",
        "info":     "notice",
    }
    status_ok = {"present"}

    grade_line = (
        f"Grade: {report.grade.value} ({report.score}/100)  "
        f"URL: {report.final_url}  "
        f"HTTPS: {'yes' if report.https else 'NO (plain HTTP!)'}"
    )

    if not report.https:
        sys.stdout.write(f"::error title=header-grade [HTTP site]::{grade_line}\n")
    elif report.grade.value in ("A+", "A"):
        sys.stdout.write(f"::notice title=header-grade::{grade_line}\n")
    elif report.grade.value in ("B", "C"):
        sys.stdout.write(f"::warning title=header-grade::{grade_line}\n")
    else:
        sys.stdout.write(f"::error title=header-grade::{grade_line}\n")

    for f in report.findings:
        if f.status.value in status_ok:
            continue
        level = _level_map.get(f.severity.value.lower(), "warning")
        # Collapse to one line — GitHub annotations cannot have newlines
        desc_oneline = f.description.replace("\n", " ").replace("|", "∣")[:200]
        impact = f"Score: {f.score_impact:+d}." if f.score_impact != 0 else ""
        msg = f"{f.title}. {impact} {desc_oneline}"
        sys.stdout.write(
            f"::{level} title={f.header} [{f.status.value}]::{msg}\n"
        )


def print_minimal(report: GradeReport) -> None:
    """One-line output: URL grade score — for scripting."""
    colour = _GRADE_COLOUR.get(report.grade.value, "white")
    console.print(
        f"[bold]{report.final_url}[/bold]  "
        f"[{colour}]{report.grade.value}[/{colour}]  "
        f"[dim]{report.score}/100[/dim]"
    )


def print_markdown(report: GradeReport, *, verbose: bool = False) -> None:
    """Print a Markdown-formatted report (suitable for GitHub PRs / wiki pages)."""
    import sys
    lines: list[str] = []

    grade_emoji = {
        "A+": "🟢", "A": "🟢", "B": "🟡", "C": "🟠",
        "D": "🔴", "E": "🔴", "F": "🔴",
    }.get(report.grade.value, "⚪")

    lines += [
        "# Security Headers Report",
        "",
        f"**URL:** {report.final_url}  ",
        f"**Grade:** {grade_emoji} **{report.grade.value}** ({report.score}/100)  ",
        f"**HTTPS:** {'Yes' if report.https else 'No — plaintext connection!'}  ",
    ]
    if report.server:
        lines.append(f"**Server:** `{report.server}` _(consider hiding this)_  ")
    lines.append("")

    lines += [
        "## Findings",
        "",
        "| # | Header | Status | Severity | Score Impact |",
        "|---|--------|--------|----------|-------------|",
    ]
    for i, f in enumerate(report.findings, 1):
        status_emoji = {
            FindingStatus.PRESENT: "✅",
            FindingStatus.WARNING: "⚠️",
            FindingStatus.MISSING: "❌",
            FindingStatus.INVALID: "❌",
        }.get(f.status, "")
        impact_str = f"`{f.score_impact:+d}`" if f.score_impact != 0 else "`0`"
        lines.append(
            f"| {i} | {f.header} | {status_emoji} {f.status.value.capitalize()} "
            f"| {f.severity.value.capitalize()} | {impact_str} |"
        )

    lines.append("")

    if verbose:
        problems = sorted(
            [f for f in report.findings if not f.is_ok],
            key=lambda f: (
                0 if f.severity == Severity.CRITICAL else
                1 if f.severity == Severity.HIGH else
                2 if f.severity == Severity.MEDIUM else
                3 if f.severity == Severity.LOW else 4
            ),
        )
        if problems:
            lines += ["## Fix Recommendations", ""]
            for f in problems:
                lines += [
                    f"### {f.header}",
                    "",
                    f"> **{f.title}**",
                    "",
                    f.description,
                    "",
                ]
                if f.current_value:
                    lines += [f"**Current value:** `{f.current_value}`", ""]
                if f.recommendation:
                    lines += [
                        "**How to fix:**",
                        "",
                        "```",
                        f.recommendation,
                        "```",
                        "",
                    ]
                if f.exploit_scenario:
                    lines += [
                        "**⚠️ How an attacker exploits this:**",
                        "",
                        "```",
                        f.exploit_scenario,
                        "```",
                        "",
                    ]
                if f.exploit_references:
                    lines += ["**Exploit / PoC resources:**", ""]
                    for ref in f.exploit_references:
                        lines.append(f"- {ref}")
                    lines.append("")
                if f.references:
                    lines += ["**Learn more:**", ""]
                    for ref in f.references:
                        lines.append(f"- {ref}")
                    lines.append("")

    passed = len(report.passed)
    total = len(report.findings)
    issues = total - passed
    lines += [
        "---",
        "",
        f"*{passed}/{total} headers OK — {issues} issue(s)*  ",
        "*Generated by [header-grade](https://github.com/youcefimohamed/header-grade)*",
    ]

    sys.stdout.write("\n".join(lines) + "\n")


def _report_to_dict(report: GradeReport) -> dict[str, object]:
    """Public alias for JSON serialisation (used by batch command)."""
    return _to_dict(report)


# ── internal helpers ──────────────────────────────────────────────────────────

def _grade_badge(grade: Grade) -> Text:
    colour = _GRADE_COLOUR.get(grade.value, "white")
    return Text(f" {grade.value} ", style=f"bold {colour} on grey23")


def _print_header(report: GradeReport) -> None:
    colour = _GRADE_COLOUR.get(report.grade.value, "white")

    https_icon = "[HTTPS]" if report.https else "[!] HTTP (not encrypted)"
    https_style = "green" if report.https else "bold red"

    score_bar = _score_bar(report.score)

    line1 = Text()
    line1.append(f" {report.grade.value} ", style=f"bold {colour} on grey23")
    line1.append(f"  {report.final_url}", style="bold")

    line2 = Text(f"  {https_icon}", style=https_style)

    line3 = Text()
    line3.append("\nScore: ", style="dim")
    line3.append_text(Text.from_markup(score_bar))
    line3.append(f"  {report.score}/100", style="bold")

    console.print()
    console.print(Panel(
        Group(line1, line2, line3),
        title="[bold]Security Headers Report[/bold]",
        border_style=colour,
        padding=(1, 2),
    ))


def _score_bar(score: int, width: int = 28) -> str:
    filled = round(score / 100 * width)
    colour = "green" if score >= 80 else "yellow" if score >= 50 else "red"
    bar = f"[{colour}]{'|' * filled}[/{colour}][dim]{'-' * (width - filled)}[/dim]"
    return bar


def _print_findings_table(report: GradeReport) -> None:
    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold dim",
        border_style="grey42",
        show_lines=False,
        padding=(0, 1),
    )
    table.add_column("", width=3, justify="center")   # icon
    table.add_column("Header", style="bold", min_width=35)
    table.add_column("Status", min_width=10)
    table.add_column("Impact", justify="right", min_width=8)

    for finding in report.findings:
        icon = _STATUS_ICON[finding.status]
        icon_colour = _STATUS_COLOUR[finding.status]
        status_label = finding.status.value.capitalize()
        impact = finding.score_impact
        impact_str = (
            f"[red]{impact:+d}[/red]" if impact < 0
            else "[dim]  0[/dim]" if impact == 0
            else f"[green]{impact:+d}[/green]"
        )
        table.add_row(
            f"[{icon_colour}]{icon}[/{icon_colour}]",
            finding.header,
            f"[{_STATUS_COLOUR[finding.status]}]{status_label}[/{_STATUS_COLOUR[finding.status]}]",
            impact_str,
        )

    console.print()
    console.print(table)


def _print_detailed_findings(report: GradeReport) -> None:
    """Print full descriptions and fix recommendations, sorted by severity."""
    problems = sorted(
        [f for f in report.findings if not f.is_ok],
        key=lambda f: (
            0 if f.severity == Severity.CRITICAL else
            1 if f.severity == Severity.HIGH else
            2 if f.severity == Severity.MEDIUM else
            3 if f.severity == Severity.LOW else 4
        ),
    )

    if not problems:
        console.print("\n[bold green]All headers look good -- nothing to detail![/bold green]")
        return

    console.print("\n[bold]── Detailed Findings ──[/bold]")

    for finding in problems:
        sev_colour = _SEVERITY_COLOUR[finding.severity]
        icon = _STATUS_ICON[finding.status]
        status_colour = _STATUS_COLOUR[finding.status]

        console.print()
        console.print(
            f"[{status_colour}]{icon}[/{status_colour}] "
            f"[bold]{finding.header}[/bold]  "
            f"[{sev_colour}][{finding.severity.value.upper()}][/{sev_colour}]"
        )
        console.print(f"  [dim]{finding.title}[/dim]")
        console.print()

        # Description
        for line in finding.description.splitlines():
            console.print(f"  {line}")

        # Current value
        if finding.current_value:
            console.print(
                f"\n  [dim]Current value:[/dim]  [italic]{finding.current_value[:120]}[/italic]"
            )

        # Recommendation
        if finding.recommendation:
            console.print("\n  [bold yellow]How to fix:[/bold yellow]")
            for line in finding.recommendation.splitlines():
                console.print(f"  {line}")

        # Exploit scenario
        if finding.exploit_scenario:
            console.print("\n  [bold red]How an attacker exploits this:[/bold red]")
            for line in finding.exploit_scenario.splitlines():
                console.print(f"  [red]{line}[/red]")

        # Exploit references
        if finding.exploit_references:
            console.print("\n  [dim red]Exploit / PoC resources:[/dim red]")
            for ref in finding.exploit_references:
                console.print(f"  [link={ref}]{ref}[/link]")

        # References
        if finding.references:
            console.print("\n  [dim]Learn more:[/dim]")
            for ref in finding.references:
                console.print(f"  [link={ref}]{ref}[/link]")

        console.print()


def _print_summary(report: GradeReport) -> None:
    passed = len(report.passed)
    total = len(report.findings)
    issues = total - passed
    warnings = len(report.warnings)

    colour = _GRADE_COLOUR.get(report.grade.value, "white")
    console.print(
        f"\n[{colour}]Grade {report.grade.value}[/{colour}]  "
        f"[dim]{passed}/{total} headers OK"
        + (f", {issues} issue(s)" if issues else "")
        + (f", {warnings} warning(s)" if warnings else "")
        + "[/dim]"
    )

    if report.server:
        console.print(
            f"[dim]Server: {report.server} -- consider hiding this to reduce fingerprinting.[/dim]"
        )


# ── JSON serialisation ────────────────────────────────────────────────────────

def _to_dict(report: GradeReport) -> dict[str, Any]:
    return {
        "url": report.url,
        "final_url": report.final_url,
        "score": report.score,
        "grade": report.grade.value,
        "https": report.https,
        "server": report.server,
        "redirect_chain": report.redirect_chain,
        "findings": [
            {
                "header": f.header,
                "status": f.status.value,
                "severity": f.severity.value,
                "score_impact": f.score_impact,
                "title": f.title,
                "description": f.description,
                "current_value": f.current_value,
                "recommendation": f.recommendation,
                "references": f.references,
                "exploit_scenario": f.exploit_scenario,
                "exploit_references": f.exploit_references,
            }
            for f in report.findings
        ],
        "summary": {
            "passed": len(report.passed),
            "total": len(report.findings),
            "critical_issues": len(report.critical_findings),
            "high_issues": len(report.high_findings),
            "warnings": len(report.warnings),
        },
    }
