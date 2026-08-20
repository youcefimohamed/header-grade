"""
header-grade CLI

Usage examples:
  header-grade check https://example.com
  header-grade check example.com --verbose
  header-grade check example.com --format json | jq '.grade'
  header-grade check example.com --format markdown > report.md
  header-grade check example.com --format github        # GitHub Actions annotations
  header-grade check example.com --min-grade B          # CI gate
  header-grade check example.com --watch 10             # re-check every 10 s

  header-grade fix example.com --platform nginx
  header-grade fix example.com --platform nextjs > next.config.js
  header-grade fix example.com                          # shows platform menu
  header-grade platforms                                 # list all 27 platforms

  header-grade batch urls.txt
  header-grade batch https://a.com https://b.com --format github

  hg example.com -v
  hg fix example.com -p vercel
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import typer

from . import __version__
from ._console import make_console
from .checker import FetchError, check_url
from .fixgen import PLATFORM_IDS, PLATFORMS, generate_fix
from .models import Grade, GradeReport
from .reporter import print_github, print_json, print_markdown, print_minimal, print_report

app = typer.Typer(
    name="header-grade",
    add_completion=True,
    rich_markup_mode="rich",
    no_args_is_help=True,
)

_err = make_console(stderr=True)

_VALID_FORMATS = {"text", "json", "minimal", "markdown", "github"}

# ── Platform categories (for `hg platforms` display) ─────────────────────────
_PLATFORM_CATEGORIES: dict[str, list[str]] = {
    "Classic servers":           ["nginx", "apache", "caddy", "traefik", "haproxy"],
    "Edge / cloud platforms":    ["vercel", "netlify", "cloudflare"],
    "JavaScript / TypeScript":   ["nextjs", "remix", "astro", "sveltekit", "nuxt",
                                  "express", "hono", "bun", "deno"],
    "Python":                    ["django", "flask", "fastapi"],
    "Java / JVM":                ["springboot"],
    "PHP":                       ["laravel"],
    "Ruby":                      ["rails"],
    ".NET":                      ["aspnet"],
    "Systems languages":         ["go", "rust-axum", "elixir"],
}

# ── Server header → platform heuristic ───────────────────────────────────────
_SERVER_HINTS: dict[str, str] = {
    "nginx":       "nginx",
    "apache":      "apache",
    "caddy":       "caddy",
    "cloudflare":  "cloudflare",
    "traefik":     "traefik",
    "haproxy":     "haproxy",
    "next.js":     "nextjs",
    "express":     "express",
    "deno":        "deno",
    "bun":         "bun",
    "gunicorn":    "fastapi",
    "uvicorn":     "fastapi",
    "django":      "django",
    "python":      "fastapi",
    "php":         "laravel",
    "iis":         "aspnet",
    "kestrel":     "aspnet",
    "openresty":   "nginx",
}


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"header-grade {__version__}")
        raise typer.Exit()


def _detect_platform_hint(report: GradeReport) -> str | None:
    """Guess the likely platform from Server / X-Powered-By response headers."""
    server_lower = (report.server or "").lower()
    for keyword, platform_id in _SERVER_HINTS.items():
        if keyword in server_lower:
            return platform_id
    return None


def _print_fix_hint(console: object, report: GradeReport, url: str) -> None:
    """Print a contextual fix-command hint at the end of a check."""
    from rich.console import Console
    c: Console = console  # type: ignore[assignment]

    detected = _detect_platform_hint(report)

    c.print()
    c.print("[bold]💡 Get a ready-to-paste fix snippet:[/bold]")
    if detected:
        c.print(
            f"   [bold cyan]hg fix {url} --platform {detected}[/bold cyan]"
            f"  [dim](detected from Server: {report.server})[/dim]"
        )
        c.print(
            f"\n   Or pick a different platform:  "
            f"[dim]{', '.join(PLATFORM_IDS[:6])} ...[/dim]"
        )
    else:
        c.print(
            f"   [bold cyan]hg fix {url} --platform <PLATFORM>[/bold cyan]"
        )
        c.print(
            "\n   27 platforms available.  See them all:  "
            "[bold cyan]hg platforms[/bold cyan]"
        )


# ---------------------------------------------------------------------------
# check (default command)
# ---------------------------------------------------------------------------

@app.command(
    name="check",
    help=(
        "Check security headers for a URL and grade them A–F.\n\n"
        "[bold]Examples:[/bold]\n\n"
        "  header-grade check https://example.com\n\n"
        "  hg check example.com --verbose\n\n"
        "  hg check example.com --format json | jq '.grade'\n\n"
        "  hg check example.com --format markdown > report.md\n\n"
        "  hg check example.com --format github    [dim]# GitHub Actions annotations[/dim]\n\n"
        "  hg check example.com --min-grade B      [dim]# CI gate[/dim]\n\n"
        "  hg check example.com --watch 10         [dim]# re-check every 10 s[/dim]"
    ),
)
def check(
    url: str = typer.Argument(..., help="URL to check (https:// added if missing)"),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Show full descriptions, fix recommendations, and attacker exploit scenarios.",
    ),
    output_format: str = typer.Option(
        "text", "--format", "-f",
        help="Output format: text, json, minimal, markdown, github.",
        show_default=True,
        metavar="FORMAT",
    ),
    min_grade: str | None = typer.Option(
        None, "--min-grade",
        help="Fail (exit 1) if grade is below this. Useful in CI. Example: --min-grade B",
        metavar="GRADE",
    ),
    timeout: float = typer.Option(15.0, "--timeout", "-t", help="Request timeout in seconds."),
    no_redirects: bool = typer.Option(False, "--no-redirects", help="Do not follow HTTP redirects."),
    no_verify_ssl: bool = typer.Option(False, "--no-verify-ssl", help="Skip SSL certificate verification."),
    watch: int = typer.Option(
        0, "--watch", "-w",
        help=(
            "Re-check the URL every N seconds until grade passes --min-grade or Ctrl-C. "
            "Useful while actively adding security headers. Example: --watch 10"
        ),
        metavar="SECONDS",
    ),
    hint: bool = typer.Option(
        True, "--hint/--no-hint",
        help="Show a quick-fix command hint at the end of text output.",
        hidden=True,
    ),
    version: bool | None = typer.Option(
        None, "--version", "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    if output_format not in _VALID_FORMATS:
        _err.print(
            f"[red]Error:[/red] --format must be one of: {', '.join(sorted(_VALID_FORMATS))}. "
            f"Got '{output_format}'."
        )
        raise typer.Exit(2)

    threshold: Grade | None = None
    if min_grade is not None:
        try:
            threshold = Grade(min_grade.upper().replace("PLUS", "+"))
        except ValueError:
            _err.print(
                f"[red]Error:[/red] --min-grade must be one of: "
                f"{', '.join(g.value for g in Grade)}. Got '{min_grade}'."
            )
            raise typer.Exit(2) from None

    if watch > 0:
        _run_watch(url, watch, threshold, timeout, no_redirects, no_verify_ssl, verbose, output_format)
        return

    report = _fetch_report(url, timeout, no_redirects, no_verify_ssl)
    _print_report(report, output_format, verbose)

    # Fix hint (text mode only, when there are issues)
    if (
        output_format == "text"
        and hint
        and any(not f.is_ok for f in report.findings)
    ):
        console = make_console()
        _print_fix_hint(console, report, url)

    _check_threshold(report, threshold, output_format)


def _fetch_report(
    url: str,
    timeout: float,
    no_redirects: bool,
    no_verify_ssl: bool,
) -> GradeReport:
    try:
        return asyncio.run(
            check_url(url, timeout=timeout,
                      follow_redirects=not no_redirects,
                      verify_ssl=not no_verify_ssl)
        )
    except FetchError as exc:
        _err.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1) from None


def _print_report(report: GradeReport, fmt: str, verbose: bool) -> None:
    if fmt == "json":
        print_json(report)
    elif fmt == "minimal":
        print_minimal(report)
    elif fmt == "markdown":
        print_markdown(report, verbose=verbose)
    elif fmt == "github":
        print_github(report)
    else:
        print_report(report, verbose=verbose)


def _check_threshold(report: GradeReport, threshold: Grade | None, output_format: str) -> None:
    if threshold is not None and report.grade < threshold:
        if output_format not in ("json", "markdown", "github"):
            _err.print(
                f"\n[bold red]FAIL:[/bold red] grade [bold]{report.grade.value}[/bold] "
                f"is below required minimum [bold]{threshold.value}[/bold]."
            )
        raise typer.Exit(1)


def _run_watch(
    url: str,
    interval: int,
    threshold: Grade | None,
    timeout: float,
    no_redirects: bool,
    no_verify_ssl: bool,
    verbose: bool,
    output_format: str,
) -> None:
    """Poll URL every `interval` seconds until threshold is met."""
    console = make_console()

    console.print(
        f"\n[bold]⟳  Watching[/bold] [cyan]{url}[/cyan] "
        f"every [bold]{interval}s[/bold] — "
        f"{'grade >= ' + threshold.value if threshold else 'Ctrl-C to stop'}\n"
    )

    attempt = 0
    while True:
        attempt += 1
        ts = time.strftime("%H:%M:%S")
        console.print(f"[dim]{ts}[/dim]  ", end="")

        try:
            report = asyncio.run(
                check_url(url, timeout=timeout,
                          follow_redirects=not no_redirects,
                          verify_ssl=not no_verify_ssl)
            )
        except FetchError as exc:
            console.print(f"[red]ERROR[/red]  {exc}")
        else:
            _grade_colour = {
                "A+": "bright_green", "A": "green",
                "B": "cyan", "C": "yellow",
                "D": "dark_orange", "E": "red", "F": "bold red",
            }.get(report.grade.value, "white")

            issues = sum(1 for f in report.findings if not f.is_ok)
            console.print(
                f"[{_grade_colour}]{report.grade.value:2s}[/{_grade_colour}]  "
                f"[bold]{report.score:3d}/100[/bold]  "
                f"[dim]{issues} issue(s)[/dim]"
            )

            if verbose:
                _print_report(report, output_format, verbose=True)

            # Stop if threshold reached
            if threshold is not None and report.grade >= threshold:
                console.print(
                    f"\n[bold green]✓  Grade {report.grade.value} reached![/bold green]  "
                    f"Score: {report.score}/100"
                )
                return

        console.print(
            f"[dim]  → next check in {interval}s ...[/dim]"
        )
        time.sleep(interval)


# ---------------------------------------------------------------------------
# platforms command
# ---------------------------------------------------------------------------

@app.command(
    name="platforms",
    help=(
        "List all supported platforms for the [bold]fix[/bold] command.\n\n"
        "[bold]Examples:[/bold]\n\n"
        "  header-grade platforms\n\n"
        "  header-grade platforms --format json\n\n"
        "  header-grade fix example.com --platform nginx"
    ),
)
def platforms_cmd(
    output_format: str = typer.Option(
        "text", "--format", "-f",
        help="Output format: text or json.",
        show_default=True,
        metavar="FORMAT",
    ),
) -> None:
    if output_format == "json":
        import json as _json
        data = [
            {"id": str(p["id"]), "label": str(p["label"]), "intro": str(p["intro"])}
            for p in PLATFORMS
        ]
        typer.echo(_json.dumps(data, indent=2))
        return

    console = make_console()
    console.print(
        f"\n[bold]Available platforms[/bold]  "
        f"[dim]({len(PLATFORMS)} total — use with `hg fix URL --platform <id>`)[/dim]\n"
    )

    id_to_entry = {str(p["id"]): p for p in PLATFORMS}

    for category, ids in _PLATFORM_CATEGORIES.items():
        console.print(f"[bold dim]{category}[/bold dim]")
        for pid in ids:
            p = id_to_entry.get(pid)
            if p is None:
                continue
            label = str(p["label"])
            intro = str(p["intro"])
            console.print(
                f"  [bold cyan]{str(p['id']):<14}[/bold cyan]"
                f"[bold]{label:<22}[/bold]"
                f"[dim]{intro}[/dim]"
            )
        console.print()

    console.print(
        "[dim]Quick start: [bold]hg fix example.com --platform nginx[/bold][/dim]\n"
    )


# ---------------------------------------------------------------------------
# fix command
# ---------------------------------------------------------------------------

@app.command(
    name="fix",
    help=(
        "Generate a platform-specific config snippet to fix missing security headers.\n\n"
        "Omit [bold]--platform[/bold] to see the full platform list.\n\n"
        "[bold]Examples:[/bold]\n\n"
        "  header-grade fix example.com --platform nginx\n\n"
        "  header-grade fix example.com --platform vercel > vercel.json\n\n"
        "  header-grade fix example.com --platform nextjs >> next.config.js\n\n"
        "  header-grade fix example.com --platform cloudflare > src/index.ts\n\n"
        "  header-grade platforms    [dim]# see all 27 platforms[/dim]"
    ),
)
def fix(
    url: str = typer.Argument(..., help="URL to analyse (https:// added if missing)"),
    platform: str | None = typer.Option(
        None, "--platform", "-p",
        help=f"Target platform. Run `hg platforms` to list all {len(PLATFORM_IDS)} options.",
        metavar="PLATFORM",
    ),
    timeout: float = typer.Option(15.0, "--timeout", "-t", help="Request timeout in seconds."),
    no_verify_ssl: bool = typer.Option(False, "--no-verify-ssl", help="Skip SSL certificate verification."),
) -> None:
    # No platform given → show menu
    if platform is None:
        console = make_console()
        console.print(
            "\n[yellow]⚠  No --platform specified.[/yellow]\n\n"
            "Run [bold cyan]hg platforms[/bold cyan] to see all 27 options, then:\n\n"
            f"  [bold cyan]hg fix {url} --platform nginx[/bold cyan]\n\n"
            "[dim]Common picks:[/dim]"
        )
        for category, ids in list(_PLATFORM_CATEGORIES.items())[:3]:
            console.print(f"  [dim]{category}:[/dim] {', '.join(ids)}")
        raise typer.Exit(0)

    if platform not in PLATFORM_IDS:
        _err.print(
            f"[red]Error:[/red] Unknown platform '{platform}'.\n"
            f"Run [bold cyan]hg platforms[/bold cyan] to see all {len(PLATFORM_IDS)} options."
        )
        raise typer.Exit(2)

    _err.print(f"[dim]Checking {url} ...[/dim]")

    try:
        report = asyncio.run(
            check_url(url, timeout=timeout, verify_ssl=not no_verify_ssl)
        )
    except FetchError as exc:
        _err.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1) from None

    _err.print(
        f"[dim]Grade: {report.grade.value} ({report.score}/100) — "
        f"generating {platform} config ...[/dim]\n"
    )

    try:
        snippet = generate_fix(report, platform)
    except ValueError as exc:
        _err.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from None

    typer.echo(snippet)


# ---------------------------------------------------------------------------
# batch command
# ---------------------------------------------------------------------------

@app.command(
    name="batch",
    help=(
        "Check multiple URLs and summarise results.\n\n"
        "Pass URLs as arguments or a file containing one URL per line.\n\n"
        "[bold]Examples:[/bold]\n\n"
        "  header-grade batch https://example.com https://other.com\n\n"
        "  header-grade batch urls.txt\n\n"
        "  header-grade batch urls.txt --format json\n\n"
        "  header-grade batch urls.txt --format github   [dim]# GitHub Actions[/dim]\n\n"
        "  header-grade batch urls.txt --min-grade B     [dim]# fail if any URL < B[/dim]"
    ),
)
def batch(
    urls_or_file: list[str] = typer.Argument(
        ..., help="URLs to check, or a single path to a text file with one URL per line."
    ),
    output_format: str = typer.Option(
        "text", "--format", "-f",
        help="Output format: text, json, minimal, markdown, github.",
        show_default=True,
        metavar="FORMAT",
    ),
    min_grade: str | None = typer.Option(
        None, "--min-grade",
        help="Fail (exit 1) if any URL's grade is below this. Useful in CI.",
        metavar="GRADE",
    ),
    timeout: float = typer.Option(15.0, "--timeout", "-t", help="Request timeout per URL in seconds."),
    no_verify_ssl: bool = typer.Option(False, "--no-verify-ssl", help="Skip SSL certificate verification."),
    concurrency: int = typer.Option(
        5, "--concurrency", "-c",
        help="Number of URLs to check concurrently.",
        show_default=True,
    ),
) -> None:
    if output_format not in _VALID_FORMATS:
        _err.print(f"[red]Error:[/red] Invalid format '{output_format}'. "
                   f"Choose from: {', '.join(sorted(_VALID_FORMATS))}")
        raise typer.Exit(2)

    threshold: Grade | None = None
    if min_grade is not None:
        try:
            threshold = Grade(min_grade.upper().replace("PLUS", "+"))
        except ValueError:
            _err.print(f"[red]Error:[/red] Invalid grade '{min_grade}'.")
            raise typer.Exit(2) from None

    # Resolve URL list
    urls: list[str] = []
    if len(urls_or_file) == 1 and Path(urls_or_file[0]).exists():
        p = Path(urls_or_file[0])
        urls = [line.strip() for line in p.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")]
    else:
        urls = list(urls_or_file)

    if not urls:
        _err.print("[red]Error:[/red] No URLs to check.")
        raise typer.Exit(2)

    console = make_console()

    async def run_batch() -> list[tuple[str, object]]:
        sem = asyncio.Semaphore(concurrency)

        async def check_one(u: str) -> tuple[str, object]:
            async with sem:
                try:
                    r = await check_url(u, timeout=timeout, verify_ssl=not no_verify_ssl)
                    return (u, r)
                except FetchError as exc:
                    return (u, exc)

        tasks = [asyncio.create_task(check_one(u)) for u in urls]
        return [await t for t in tasks]

    results = asyncio.run(run_batch())

    any_fail = False
    import json as _json

    if output_format == "json":
        output = []
        for url, result in results:
            if isinstance(result, FetchError):
                output.append({"url": url, "error": str(result)})
            else:
                from .reporter import _report_to_dict
                output.append(_report_to_dict(result))  # type: ignore[arg-type]
        typer.echo(_json.dumps(output, indent=2))

    elif output_format == "github":
        for url, result in results:
            if isinstance(result, FetchError):
                typer.echo(f"::error title=header-grade::Failed to fetch {url}: {result}")
                any_fail = True
            else:
                r: GradeReport = result  # type: ignore[assignment]
                print_github(r)
                if threshold and r.grade < threshold:
                    any_fail = True

    elif output_format == "markdown":
        lines = ["# Security Headers Batch Report\n"]
        lines.append("| URL | Grade | Score | Issues |")
        lines.append("|-----|-------|-------|--------|")
        for url, result in results:
            if isinstance(result, FetchError):
                lines.append(f"| {url} | ERROR | — | {result} |")
                any_fail = True
            else:
                from .models import FindingStatus
                r_md: GradeReport = result  # type: ignore[assignment]
                issues = sum(
                    1 for f in r_md.findings
                    if f.status in (FindingStatus.MISSING, FindingStatus.WARNING, FindingStatus.INVALID)
                )
                lines.append(
                    f"| {r_md.final_url} | **{r_md.grade.value}** | {r_md.score}/100 | {issues} |"
                )
                if threshold and r_md.grade < threshold:
                    any_fail = True
        typer.echo("\n".join(lines))

    else:
        # text / minimal
        for url, result in results:
            if isinstance(result, FetchError):
                console.print(f"[bold red]ERROR[/bold red]  {url}  ->  {result}")
                any_fail = True
                continue

            from .models import FindingStatus
            r_t: GradeReport = result  # type: ignore[assignment]

            grade_color = {
                "A+": "bright_green", "A": "green",
                "B": "cyan", "C": "yellow",
                "D": "yellow", "E": "red", "F": "red",
            }.get(r_t.grade.value, "white")

            if output_format == "minimal":
                console.print(
                    f"[{grade_color}]{r_t.grade.value:2s}[/{grade_color}]"
                    f"  {r_t.score:3d}/100  {r_t.final_url}"
                )
            else:
                from .models import FindingStatus
                issues = sum(
                    1 for f in r_t.findings
                    if f.status in (FindingStatus.MISSING, FindingStatus.WARNING, FindingStatus.INVALID)
                )
                console.print(
                    f"[{grade_color}]{r_t.grade.value:2s}[/{grade_color}]"
                    f"  {r_t.score:3d}/100  {r_t.final_url}"
                    f"  [{issues} issue(s)]"
                )

            if threshold and r_t.grade < threshold:
                any_fail = True

    if any_fail:
        if threshold and output_format not in ("json", "markdown", "github"):
            _err.print(
                f"\n[bold red]FAIL:[/bold red] one or more URLs scored below "
                f"[bold]{threshold.value}[/bold]."
            )
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# root callback
# ---------------------------------------------------------------------------

@app.callback()
def _root(
    version: bool | None = typer.Option(
        None, "--version", "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Security headers grader — check any URL, get an A–F grade with fix suggestions."""


# ---------------------------------------------------------------------------
# Entry-point wrapper — default-to-check routing
# ---------------------------------------------------------------------------

# Known top-level subcommands; anything else is forwarded to 'check'
_SUBCOMMANDS = frozenset({
    "check", "fix", "batch", "platforms",
    "--help", "-h", "--version", "-V",
    "--install-completion", "--show-completion",
})


def main() -> None:
    """
    CLI entry point.

    Routes bare ``hg <url> [opts]`` to ``hg check <url> [opts]`` automatically,
    so both of these work identically::

        hg example.com --verbose
        hg check example.com --verbose
    """
    import sys

    args = sys.argv[1:]
    if args:
        first = args[0]
        # If the first arg is not a flag and not a known subcommand, route to check
        if not first.startswith("-") and first not in _SUBCOMMANDS:
            sys.argv.insert(1, "check")

    app()


if __name__ == "__main__":
    main()
