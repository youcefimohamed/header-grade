"""
Platform-specific fix guide generator.

Given a GradeReport, emits a ready-to-paste config snippet for the
chosen platform that adds every missing or weak security header.
"""

from __future__ import annotations

import json as _json

from .models import FindingStatus, GradeReport

_STRONG_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "upgrade-insecure-requests"
)


def _headers_to_add(report: GradeReport) -> dict[str, str]:
    """Return {header_name: recommended_value} for all missing/weak findings."""
    to_add: dict[str, str] = {}
    for finding in report.findings:
        if finding.status not in (
            FindingStatus.MISSING,
            FindingStatus.WARNING,
            FindingStatus.INVALID,
        ):
            continue
        name = finding.header.split("/")[0].strip().lower()
        if "csp" in name or "content-security" in name:
            to_add["Content-Security-Policy"] = _STRONG_CSP
        elif "hsts" in name or "strict-transport" in name:
            to_add["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )
        elif "x-frame" in name:
            to_add["X-Frame-Options"] = "DENY"
        elif "x-content-type" in name:
            to_add["X-Content-Type-Options"] = "nosniff"
        elif "referrer" in name:
            to_add["Referrer-Policy"] = "strict-origin-when-cross-origin"
        elif "permissions" in name:
            to_add["Permissions-Policy"] = (
                "camera=(), microphone=(), geolocation=(), "
                "payment=(), usb=(), interest-cohort=()"
            )
        elif "opener" in name or "coop" in name:
            to_add["Cross-Origin-Opener-Policy"] = "same-origin"
        elif "embedder" in name or "coep" in name:
            to_add["Cross-Origin-Embedder-Policy"] = "require-corp"
        elif "resource-policy" in name or "corp" in name:
            to_add["Cross-Origin-Resource-Policy"] = "same-origin"
        elif "origin-agent" in name:
            to_add["Origin-Agent-Cluster"] = "?1"
        elif "cache" in name:
            to_add["Cache-Control"] = "no-store, no-cache, must-revalidate"
        elif "reporting" in name:
            to_add["Reporting-Endpoints"] = 'default="https://your-domain.com/reports"'
    return to_add


# ---------------------------------------------------------------------------
# Platform builders — Original 17
# ---------------------------------------------------------------------------


def _nginx(headers: dict[str, str]) -> str:
    lines = [
        "# Add inside your server { } block:",
        "",
        "server_tokens off;  # Remove nginx version from Server header",
        "",
    ]
    for h, v in headers.items():
        lines.append(f'add_header {h} "{v}" always;')
    lines += [
        "",
        "# Reload after editing:",
        "#   nginx -t && systemctl reload nginx",
    ]
    return "\n".join(lines)


def _apache(headers: dict[str, str]) -> str:
    lines = [
        "# .htaccess or VirtualHost config (requires mod_headers):",
        "# Enable: a2enmod headers",
        "",
        "ServerTokens Prod",
        "ServerSignature Off",
        "",
        "<IfModule mod_headers.c>",
    ]
    for h, v in headers.items():
        lines.append(f'    Header always set {h} "{v}"')
    lines += [
        "    Header always unset X-Powered-By",
        "    Header always unset Server",
        "</IfModule>",
        "",
        "# Restart: systemctl restart apache2",
    ]
    return "\n".join(lines)


def _caddy(headers: dict[str, str]) -> str:
    lines = [
        "# Inside your Caddyfile site block:",
        "",
        "header {",
    ]
    for h, v in headers.items():
        lines.append(f'    {h} "{v}"')
    lines += [
        "    -Server",
        "    -X-Powered-By",
        "}",
        "",
        "# Reload: caddy reload",
    ]
    return "\n".join(lines)


def _vercel(headers: dict[str, str]) -> str:
    header_list = [{"key": h, "value": v} for h, v in headers.items()]
    config = {
        "headers": [
            {
                "source": "/(.*)",
                "headers": header_list,
            }
        ]
    }
    return (
        "// vercel.json — add or merge into your existing file:\n\n"
        + _json.dumps(config, indent=2)
    )


def _netlify(headers: dict[str, str]) -> str:
    lines = [
        "# _headers file (place at your publish directory root):",
        "",
        "/*",
    ]
    for h, v in headers.items():
        lines.append(f"  {h}: {v}")
    return "\n".join(lines)


def _nextjs(headers: dict[str, str]) -> str:
    entries = ",\n        ".join(
        f'{{ key: "{h}", value: "{v}" }}' for h, v in headers.items()
    )
    return (
        "// next.config.js\n\n"
        "/** @type {import('next').NextConfig} */\n"
        "const nextConfig = {\n"
        "  poweredByHeader: false,  // Remove X-Powered-By: Next.js\n"
        "  async headers() {\n"
        "    return [\n"
        "      {\n"
        '        source: "/(.*)",\n'
        "        headers: [\n"
        f"        {entries},\n"
        "        ],\n"
        "      },\n"
        "    ];\n"
        "  },\n"
        "};\n\n"
        "module.exports = nextConfig;"
    )


def _express_helmet(headers: dict[str, str]) -> str:
    lines = [
        "// Express.js — install helmet: npm install helmet",
        "",
        "const helmet = require('helmet');",
        "",
        "app.use(helmet({",
        "  contentSecurityPolicy: {",
        "    directives: {",
        "      defaultSrc: [\"'self'\"],",
        "      scriptSrc: [\"'self'\"],",
        "      styleSrc: [\"'self'\"],",
        "      imgSrc: [\"'self'\", 'data:'],",
        "      objectSrc: [\"'none'\"],",
        "      frameAncestors: [\"'none'\"],",
        "      upgradeInsecureRequests: [],",
        "    },",
        "  },",
        "  crossOriginOpenerPolicy: { policy: 'same-origin' },",
        "  crossOriginEmbedderPolicy: { policy: 'require-corp' },",
        "  crossOriginResourcePolicy: { policy: 'same-origin' },",
        "  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },",
        "  frameguard: { action: 'deny' },",
        "  noSniff: true,",
        "  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },",
        "  hidePoweredBy: true,",
        "}));",
    ]
    extra = {
        h: v
        for h, v in headers.items()
        if not any(
            k in h
            for k in [
                "Content-Security-Policy",
                "Cross-Origin",
                "Strict-Transport",
                "X-Frame",
                "X-Content",
                "Referrer",
            ]
        )
    }
    if extra:
        lines.append("")
        lines.append("// Additional headers not covered by helmet:")
        for h, v in extra.items():
            lines.append(
                f"app.use((_req, res, next) => {{ res.setHeader('{h}', '{v}'); next(); }});"
            )
    return "\n".join(lines)


def _django(headers: dict[str, str]) -> str:
    return """\
# settings.py — Django SecurityMiddleware covers most headers.
# Ensure SecurityMiddleware is FIRST in MIDDLEWARE list.

SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SECURE = True

# CSP — pip install django-csp
# Add 'csp.middleware.CSPMiddleware' to MIDDLEWARE
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_OBJECT_SRC = ("'none'",)
CSP_FRAME_ANCESTORS = ("'none'",)

# Permissions-Policy — pip install django-permissions-policy
PERMISSIONS_POLICY = {
    "camera": [],
    "microphone": [],
    "geolocation": [],
    "payment": [],
}"""


def _flask(headers: dict[str, str]) -> str:
    lines = [
        "# pip install flask-talisman",
        "",
        "from flask import Flask",
        "from flask_talisman import Talisman",
        "",
        "app = Flask(__name__)",
        "Talisman(app,",
        "    force_https=True,",
        "    strict_transport_security=True,",
        "    strict_transport_security_max_age=31536000,",
        "    strict_transport_security_include_subdomains=True,",
        "    strict_transport_security_preload=True,",
        "    frame_options='DENY',",
        "    content_type_options=True,",
        "    referrer_policy='strict-origin-when-cross-origin',",
        "    content_security_policy={",
        "        'default-src': \"'self'\",",
        "        'script-src': \"'self'\",",
        "        'object-src': \"'none'\",",
        "        'frame-ancestors': \"'none'\",",
        "    },",
        ")",
        "",
        "@app.after_request",
        "def extra_headers(response):",
    ]
    for h, v in headers.items():
        if h not in ("Content-Security-Policy", "Strict-Transport-Security",
                     "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"):
            lines.append(f'    response.headers["{h}"] = "{v}"')
    lines += ["    return response"]
    return "\n".join(lines)


def _fastapi(headers: dict[str, str]) -> str:
    lines = [
        "from fastapi import FastAPI, Request",
        "from starlette.middleware.base import BaseHTTPMiddleware",
        "from starlette.responses import Response",
        "",
        "SECURITY_HEADERS = {",
    ]
    for h, v in headers.items():
        lines.append(f'    "{h}": "{v}",')
    lines += [
        "}",
        "",
        "class SecurityHeadersMiddleware(BaseHTTPMiddleware):",
        "    async def dispatch(self, request: Request, call_next):",
        "        response: Response = await call_next(request)",
        "        for key, value in SECURITY_HEADERS.items():",
        "            response.headers[key] = value",
        "        response.headers.pop('server', None)  # Remove info disclosure",
        "        return response",
        "",
        "app = FastAPI()",
        "app.add_middleware(SecurityHeadersMiddleware)",
    ]
    return "\n".join(lines)


def _spring_boot(headers: dict[str, str]) -> str:
    return (
        "// SecurityConfig.java\n\n"
        "@Bean\n"
        "public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {\n"
        "    http.headers(h -> h\n"
        '        .contentSecurityPolicy(csp -> csp.policyDirectives("' + _STRONG_CSP + '"))\n'
        "        .frameOptions(f -> f.deny())\n"
        "        .contentTypeOptions(Customizer.withDefaults())\n"
        "        .httpStrictTransportSecurity(hsts -> hsts\n"
        "            .maxAgeInSeconds(31536000)\n"
        "            .includeSubDomains(true)\n"
        "            .preload(true))\n"
        "        .referrerPolicy(r -> r.policy(\n"
        "            ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))\n"
        '        .permissionsPolicy(p -> p.policy("camera=(), microphone=(), geolocation=()"))\n'
        "        .crossOriginOpenerPolicy(c -> c\n"
        "            .policy(CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy.SAME_ORIGIN))\n"
        "    );\n"
        "    return http.build();\n"
        "}"
    )


def _laravel(headers: dict[str, str]) -> str:
    lines = [
        "<?php",
        "// php artisan make:middleware SecurityHeaders",
        "// Register in app/Http/Kernel.php -> $middleware",
        "",
        "namespace App\\Http\\Middleware;",
        "use Closure; use Illuminate\\Http\\Request;",
        "",
        "class SecurityHeaders {",
        "    public function handle(Request $request, Closure $next) {",
        "        $response = $next($request);",
    ]
    for h, v in headers.items():
        lines.append(f"        $response->headers->set('{h}', '{v}');")
    lines += [
        "        $response->headers->remove('X-Powered-By');",
        "        return $response;",
        "    }",
        "}",
        "",
        "# Also in php.ini: expose_php = Off",
        "# Also in config/session.php: 'secure' => true, 'http_only' => true, 'same_site' => 'lax'",
    ]
    return "\n".join(lines)


def _rails(headers: dict[str, str]) -> str:
    lines = [
        "# Gemfile: gem 'secure_headers'",
        "# config/initializers/secure_headers.rb",
        "",
        "SecureHeaders::Configuration.default do |config|",
        "  config.hsts = 'max-age=31536000; includeSubDomains; preload'",
        "  config.x_frame_options = 'DENY'",
        "  config.x_content_type_options = 'nosniff'",
        "  config.referrer_policy = %w[strict-origin-when-cross-origin]",
        "  config.csp = {",
        "    default_src: %w['self'],",
        "    script_src:  %w['self'],",
        "    object_src:  %w['none'],",
        "    frame_ancestors: %w['none'],",
        "    upgrade_insecure_requests: true,",
        "  }",
        "  config.permissions_policy = {",
        "    camera: [], microphone: [], geolocation: [], payment: [],",
        "  }",
        "end",
        "",
        "# config/application.rb",
    ]
    custom = {h: v for h, v in headers.items() if "Content-Security-Policy" not in h}
    if custom:
        lines.append("Rails.application.config.action_dispatch.default_headers.merge!(")
        for h, v in custom.items():
            lines.append(f"  '{h}' => '{v}',")
        lines.append(")")
    return "\n".join(lines)


def _aspnet(headers: dict[str, str]) -> str:
    lines = [
        "// Program.cs (.NET 6+)",
        "",
        "builder.Services.AddHsts(opt => {",
        "    opt.MaxAge = TimeSpan.FromSeconds(31536000);",
        "    opt.IncludeSubDomains = true;",
        "    opt.Preload = true;",
        "});",
        "",
        "var app = builder.Build();",
        "app.UseHttpsRedirection();",
        "app.UseHsts();",
        "",
        "app.Use(async (context, next) => {",
        "    var h = context.Response.Headers;",
    ]
    for h, v in headers.items():
        lines.append(f'    h["{h}"] = "{v}";')
    lines += [
        '    h.Remove("Server");',
        '    h.Remove("X-Powered-By");',
        '    h.Remove("X-AspNet-Version");',
        "    await next();",
        "});",
        "",
        "// web.config — remove IIS headers:",
        "// <security><requestFiltering removeServerHeader='true' /></security>",
        "// <httpProtocol><customHeaders><remove name='X-Powered-By' /></customHeaders></httpProtocol>",
    ]
    return "\n".join(lines)


def _go(headers: dict[str, str]) -> str:
    lines = [
        "// Go (net/http) — security headers middleware",
        "",
        "func securityHeaders(next http.Handler) http.Handler {",
        "    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {",
    ]
    for h, v in headers.items():
        lines.append(f'        w.Header().Set("{h}", "{v}")')
    lines += [
        '        w.Header().Del("Server")',
        "        next.ServeHTTP(w, r)",
        "    })",
        "}",
        "",
        "// Wrap your mux:",
        "// http.ListenAndServeTLS(':443', certFile, keyFile, securityHeaders(mux))",
    ]
    return "\n".join(lines)


def _sveltekit(headers: dict[str, str]) -> str:
    lines = [
        "// src/hooks.server.ts",
        "",
        "import type { Handle } from '@sveltejs/kit';",
        "",
        "export const handle: Handle = async ({ event, resolve }) => {",
        "  const response = await resolve(event);",
    ]
    for h, v in headers.items():
        lines.append(f'  response.headers.set("{h}", "{v}");')
    lines += [
        '  response.headers.delete("X-Powered-By");',
        "  return response;",
        "};",
    ]
    return "\n".join(lines)


def _nuxt(headers: dict[str, str]) -> str:
    entries = "\n".join(
        f"        '{h}': '{v}'," for h, v in headers.items()
    )
    return (
        "// nuxt.config.ts\n\n"
        "export default defineNuxtConfig({\n"
        "  routeRules: {\n"
        "    '/**': {\n"
        "      headers: {\n"
        f"{entries}\n"
        "      },\n"
        "    },\n"
        "  },\n"
        "});\n\n"
        "// Or use the nuxt-security module for nonce support:\n"
        "// npm install nuxt-security"
    )


# ---------------------------------------------------------------------------
# New platforms — 2025/2026
# ---------------------------------------------------------------------------


def _cloudflare(headers: dict[str, str]) -> str:
    """Cloudflare Workers (wrangler) + Pages (_headers file)."""
    # Workers handler
    header_sets = "\n".join(
        f'    response.headers.set("{h}", "{v}");' for h, v in headers.items()
    )
    worker = (
        "// ── Cloudflare Workers ──────────────────────────────────────────────\n"
        "// src/index.ts  (or index.js)\n\n"
        "export default {\n"
        "  async fetch(request: Request, env: Env): Promise<Response> {\n"
        "    const response = await fetch(request);\n"
        "    const newResponse = new Response(response.body, response);\n\n"
        f"{header_sets}\n"
        '    newResponse.headers.delete("Server");\n'
        '    newResponse.headers.delete("X-Powered-By");\n\n'
        "    return newResponse;\n"
        "  },\n"
        "};\n"
    )

    # Pages _headers file
    pages_lines = [
        "\n// ── Cloudflare Pages ────────────────────────────────────────────────",
        "// Create a _headers file in your output directory (e.g. dist/):",
        "",
        "/*",
    ]
    for h, v in headers.items():
        pages_lines.append(f"  {h}: {v}")
    pages_lines += [
        "",
        "// Docs: https://developers.cloudflare.com/pages/configuration/headers/",
    ]
    return worker + "\n".join(pages_lines)


def _deno(headers: dict[str, str]) -> str:
    """Deno / Deno Deploy using Deno.serve() or Oak framework."""
    header_sets = "\n".join(
        f'    headers.set("{h}", "{v}");' for h, v in headers.items()
    )
    return (
        "// Deno — src/server.ts\n"
        "// Works with Deno.serve() (Deno 1.35+) and Deno Deploy\n\n"
        "Deno.serve(async (req: Request) => {\n"
        "  // ... your handler logic ...\n"
        "  const body = 'Hello, World!';\n\n"
        "  const headers = new Headers({\n"
        '    "Content-Type": "text/html; charset=utf-8",\n'
        "  });\n\n"
        f"  // Security headers\n"
        f"{header_sets}\n\n"
        "  return new Response(body, { headers });\n"
        "});\n\n"
        "// ── Using Oak framework ──────────────────────────────────────────────\n"
        "// import { Application } from 'jsr:@oak/oak';\n"
        "// const app = new Application();\n"
        "// app.use(async (ctx, next) => {\n"
        "//   await next();\n"
        + "".join(
            f'//   ctx.response.headers.set("{h}", "{v}");\n'
            for h, v in headers.items()
        )
        + "// });"
    )


def _bun(headers: dict[str, str]) -> str:
    """Bun HTTP server (Bun.serve) — Bun 1.x."""
    header_obj = _json.dumps(dict(headers), indent=4)
    return (
        "// Bun — server.ts\n"
        "// Bun 1.x native HTTP server\n\n"
        "const SECURITY_HEADERS: Record<string, string> = "
        + header_obj
        + ";\n\n"
        "Bun.serve({\n"
        "  port: 3000,\n\n"
        "  async fetch(req: Request): Promise<Response> {\n"
        "    // ... your routing logic ...\n"
        "    const body = 'Hello from Bun!';\n\n"
        "    return new Response(body, {\n"
        "      headers: {\n"
        '        "Content-Type": "text/html",\n'
        "        ...SECURITY_HEADERS,\n"
        "      },\n"
        "    });\n"
        "  },\n\n"
        "  // Remove Bun's default Server header\n"
        "  development: false,\n"
        "});\n\n"
        "// ── With Elysia (Bun's main framework) ───────────────────────────────\n"
        "// npm install elysia\n"
        "// import { Elysia } from 'elysia';\n"
        "// new Elysia()\n"
        "//   .onBeforeHandle(({ set }) => {\n"
        "//     Object.assign(set.headers, SECURITY_HEADERS);\n"
        "//   })\n"
        "//   .listen(3000);"
    )


def _hono(headers: dict[str, str]) -> str:
    """Hono framework — runs on Cloudflare, Bun, Deno, Node, Lambda."""
    # Check which headers are already handled by hono/secure-headers
    hono_covered = {
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Embedder-Policy",
        "Cross-Origin-Resource-Policy",
    }
    extra = {h: v for h, v in headers.items() if h not in hono_covered}

    lines = [
        "// Hono — src/index.ts",
        "// Works on: Cloudflare Workers, Bun, Deno, Node.js, AWS Lambda",
        "// npm install hono",
        "",
        "import { Hono } from 'hono';",
        "import { secureHeaders } from 'hono/secure-headers';",
        "",
        "const app = new Hono();",
        "",
        "// Built-in security headers middleware (Hono v4+)",
        "app.use('*', secureHeaders({",
        "  contentSecurityPolicy: {",
        "    defaultSrc: [\"'self'\"],",
        "    scriptSrc: [\"'self'\"],",
        "    styleSrc: [\"'self'\"],",
        "    imgSrc: [\"'self'\", 'data:'],",
        "    objectSrc: [\"'none'\"],",
        "    frameAncestors: [\"'none'\"],",
        "    upgradeInsecureRequests: [],",
        "  },",
        "  strictTransportSecurity: 'max-age=31536000; includeSubDomains; preload',",
        "  xFrameOptions: 'DENY',",
        "  xContentTypeOptions: 'nosniff',",
        "  referrerPolicy: 'strict-origin-when-cross-origin',",
        "  crossOriginOpenerPolicy: 'same-origin',",
        "  crossOriginEmbedderPolicy: 'require-corp',",
        "  crossOriginResourcePolicy: 'same-origin',",
        "  permissionsPolicy: {",
        "    camera: [],",
        "    microphone: [],",
        "    geolocation: [],",
        "  },",
        "}));",
    ]
    if extra:
        lines += [
            "",
            "// Additional headers not covered by secureHeaders():",
            "app.use('*', async (c, next) => {",
            "  await next();",
        ]
        for h, v in extra.items():
            lines.append(f'  c.header("{h}", "{v}");')
        lines.append("});")

    lines += [
        "",
        "export default app;",
    ]
    return "\n".join(lines)


def _remix(headers: dict[str, str]) -> str:
    """Remix (React Router v7) — app/entry.server.tsx."""
    header_sets = "\n".join(
        f'  responseHeaders.set("{h}", "{v}");' for h, v in headers.items()
    )
    return (
        "// app/entry.server.tsx — Remix / React Router v7\n\n"
        "import type { EntryContext } from '@remix-run/node';\n"
        "import { RemixServer } from '@remix-run/react';\n"
        "import { renderToString } from 'react-dom/server';\n\n"
        "export default function handleRequest(\n"
        "  request: Request,\n"
        "  responseStatusCode: number,\n"
        "  responseHeaders: Headers,\n"
        "  remixContext: EntryContext\n"
        ") {\n"
        "  // Security headers — applied to every server response\n"
        f"{header_sets}\n\n"
        "  const markup = renderToString(\n"
        "    <RemixServer context={remixContext} url={request.url} />\n"
        "  );\n\n"
        '  responseHeaders.set("Content-Type", "text/html");\n\n'
        "  return new Response('<!DOCTYPE html>' + markup, {\n"
        "    status: responseStatusCode,\n"
        "    headers: responseHeaders,\n"
        "  });\n"
        "}\n\n"
        "// ── Per-route headers ────────────────────────────────────────────────\n"
        "// In any route file (app/routes/index.tsx):\n"
        "// export function headers() {\n"
        "//   return { 'Cache-Control': 'no-store' };\n"
        "// }"
    )


def _astro(headers: dict[str, str]) -> str:
    """Astro SSR + static adapters."""
    # Netlify/Vercel-style _headers file (static export)
    static_headers = "\n".join(f"  {h}: {v}" for h, v in headers.items())
    # Middleware approach (SSR)
    mw_sets = "\n".join(
        f'  res.headers.set("{h}", "{v}");' for h, v in headers.items()
    )

    return (
        "// ── Astro SSR — src/middleware.ts ───────────────────────────────────\n"
        "// Works with any SSR adapter (Node, Cloudflare, Vercel, Netlify)\n\n"
        "import { defineMiddleware } from 'astro:middleware';\n\n"
        "export const onRequest = defineMiddleware(async (_ctx, next) => {\n"
        "  const res = await next();\n\n"
        f"{mw_sets}\n"
        '  res.headers.delete("X-Powered-By");\n\n'
        "  return res;\n"
        "});\n\n"
        "// ── Static export — public/_headers (Netlify/Cloudflare Pages) ──────\n"
        "/*\n"
        "/*\n"
        f"{static_headers}\n"
        "*/\n\n"
        "// ── Vercel adapter — astro.config.mjs ───────────────────────────────\n"
        "// import vercel from '@astrojs/vercel/serverless';\n"
        "// export default defineConfig({\n"
        "//   output: 'server',\n"
        "//   adapter: vercel({ headers: { ... } }),\n"
        "// });"
    )


def _traefik(headers: dict[str, str]) -> str:
    """Traefik v3 reverse proxy — YAML dynamic config."""
    header_yaml = "\n".join(
        f"        {h}: \"{v}\"" for h, v in headers.items()
    )
    return (
        "# Traefik v3 — dynamic configuration file\n"
        "# Place in your dynamic config directory (e.g. config/security-headers.yml)\n\n"
        "http:\n"
        "  middlewares:\n"
        "    security-headers:\n"
        "      headers:\n"
        "        # Security headers\n"
        f"{header_yaml}\n"
        "        # Server info suppression\n"
        "        customResponseHeaders:\n"
        '          Server: ""\n'
        '          X-Powered-By: ""\n'
        "        # HSTS\n"
        "        stsSeconds: 31536000\n"
        "        stsIncludeSubdomains: true\n"
        "        stsPreload: true\n"
        "        forceSTSHeader: true\n"
        "        # Frame options\n"
        "        frameDeny: true\n"
        "        # MIME sniffing\n"
        "        contentTypeNosniff: true\n"
        "        # Referrer\n"
        "        referrerPolicy: strict-origin-when-cross-origin\n\n"
        "  routers:\n"
        "    my-app:\n"
        "      rule: Host(`example.com`)\n"
        "      middlewares:\n"
        "        - security-headers   # <-- attach here\n"
        "      service: my-service\n\n"
        "# OR use Docker labels:\n"
        "# traefik.http.middlewares.sec.headers.contentSecurityPolicy=default-src 'self'\n"
        "# traefik.http.routers.my-app.middlewares=sec"
    )


def _haproxy(headers: dict[str, str]) -> str:
    """HAProxy 2.x — haproxy.cfg."""
    header_lines = "\n".join(
        f"    http-response set-header {h} \"{v}\"" for h, v in headers.items()
    )
    return (
        "# HAProxy 2.x — haproxy.cfg\n"
        "# Add inside your frontend or backend section:\n\n"
        "frontend https-in\n"
        "    bind *:443 ssl crt /etc/ssl/certs/example.pem\n"
        "    mode http\n"
        "    option forwardfor\n\n"
        "    # Security response headers\n"
        f"{header_lines}\n"
        "    http-response del-header Server\n"
        "    http-response del-header X-Powered-By\n\n"
        "    # HSTS (HAProxy native directive)\n"
        "    http-response set-header Strict-Transport-Security \\\n"
        "        \"max-age=31536000; includeSubDomains; preload\"\n\n"
        "    default_backend app-servers\n\n"
        "backend app-servers\n"
        "    balance roundrobin\n"
        "    server app1 127.0.0.1:8080 check\n\n"
        "# Reload: haproxy -f /etc/haproxy/haproxy.cfg -c && systemctl reload haproxy"
    )


def _rust_axum(headers: dict[str, str]) -> str:
    """Rust — Axum framework + tower-http security headers layer."""
    header_inserts = "\n".join(
        f'        .insert("{h}", HeaderValue::from_static("{v}"))'
        for h, v in headers.items()
    )
    return (
        "// Rust — Cargo.toml dependencies:\n"
        "// axum = \"0.7\"\n"
        "// tower-http = { version = \"0.5\", features = [\"set-headers\"] }\n"
        "// tokio = { version = \"1\", features = [\"full\"] }\n\n"
        "use axum::{Router, routing::get};\n"
        "use http::{header, HeaderMap, HeaderValue};\n"
        "use tower_http::set_header::SetResponseHeaderLayer;\n\n"
        "fn security_headers() -> HeaderMap {\n"
        "    let mut map = HeaderMap::new();\n"
        f"{header_inserts}\n"
        '    map.insert("Server", HeaderValue::from_static(""));\n'
        "    map\n"
        "}\n\n"
        "#[tokio::main]\n"
        "async fn main() {\n"
        "    let app = Router::new()\n"
        '        .route("/", get(handler))\n'
        "        .layer(\n"
        "            tower_http::set_header::SetResponseHeadersLayer::new(\n"
        "                security_headers()\n"
        "            )\n"
        "        );\n\n"
        "    let listener = tokio::net::TcpListener::bind(\"0.0.0.0:3000\").await.unwrap();\n"
        "    axum::serve(listener, app).await.unwrap();\n"
        "}\n\n"
        "// ── Using the dedicated tower-http SecureHeaders layer (simpler) ─────\n"
        "// use tower_http::sensitive_headers::SetSensitiveResponseHeadersLayer;\n"
        "// or craft a custom layer — Axum 0.7 + tower-http 0.5 both stable on\n"
        "// crates.io as of 2025."
    )


def _elixir_phoenix(headers: dict[str, str]) -> str:
    """Elixir — Phoenix framework plug."""
    plug_sets = "\n".join(
        f'    |> put_resp_header("{h.lower()}", "{v}")'
        for h, v in headers.items()
    )
    return (
        "# lib/my_app_web/plugs/security_headers.ex\n\n"
        "defmodule MyAppWeb.Plugs.SecurityHeaders do\n"
        "  @moduledoc \"\"\"Adds security headers to every response.\"\"\"\n"
        "  import Plug.Conn\n\n"
        "  def init(opts), do: opts\n\n"
        "  def call(conn, _opts) do\n"
        "    conn\n"
        f"{plug_sets}\n"
        '    |> delete_resp_header("server")\n'
        '    |> delete_resp_header("x-powered-by")\n'
        "  end\n"
        "end\n\n"
        "# lib/my_app_web/router.ex — add to your pipeline(s):\n\n"
        "defmodule MyAppWeb.Router do\n"
        "  use MyAppWeb, :router\n\n"
        "  pipeline :browser do\n"
        "    plug :accepts, [\"html\"]\n"
        "    plug :fetch_session\n"
        "    plug :protect_from_forgery\n"
        "    plug MyAppWeb.Plugs.SecurityHeaders   # <-- here\n"
        "  end\n\n"
        "  # config/config.exs — session security:\n"
        "  # config :my_app, MyAppWeb.Endpoint,\n"
        "  #   http: [only_cookie_options: [secure: true, http_only: true, same_site: \"Lax\"]]\n"
        "end"
    )


# ---------------------------------------------------------------------------
# Platform registry
# ---------------------------------------------------------------------------

PLATFORMS: list[dict[str, object]] = [
    # ── Classic servers ───────────────────────────────────────────────────────
    {"id": "nginx",      "label": "Nginx",              "intro": "Inside server {} block (nginx.conf)",                    "builder": _nginx},
    {"id": "apache",     "label": "Apache",             "intro": ".htaccess or VirtualHost (requires mod_headers)",        "builder": _apache},
    {"id": "caddy",      "label": "Caddy",              "intro": "Inside your Caddyfile site block",                       "builder": _caddy},
    {"id": "traefik",    "label": "Traefik",            "intro": "Dynamic config YAML + Docker labels",                    "builder": _traefik},
    {"id": "haproxy",    "label": "HAProxy",            "intro": "haproxy.cfg frontend/backend section",                   "builder": _haproxy},
    # ── Edge / cloud platforms ────────────────────────────────────────────────
    {"id": "vercel",     "label": "Vercel",             "intro": "vercel.json at project root",                            "builder": _vercel},
    {"id": "netlify",    "label": "Netlify",            "intro": "_headers file at publish directory root",                "builder": _netlify},
    {"id": "cloudflare", "label": "Cloudflare",         "intro": "Cloudflare Workers (src/index.ts) + Pages (_headers)",   "builder": _cloudflare},
    # ── JavaScript / TypeScript runtimes & frameworks ─────────────────────────
    {"id": "nextjs",     "label": "Next.js",            "intro": "next.config.js at project root",                         "builder": _nextjs},
    {"id": "remix",      "label": "Remix",              "intro": "app/entry.server.tsx + per-route headers()",             "builder": _remix},
    {"id": "astro",      "label": "Astro",              "intro": "src/middleware.ts (SSR) or public/_headers (static)",    "builder": _astro},
    {"id": "sveltekit",  "label": "SvelteKit",          "intro": "src/hooks.server.ts",                                    "builder": _sveltekit},
    {"id": "nuxt",       "label": "Nuxt",               "intro": "nuxt.config.ts",                                         "builder": _nuxt},
    {"id": "express",    "label": "Express/Helmet",     "intro": "Express app entry file (app.js / server.js)",            "builder": _express_helmet},
    {"id": "hono",       "label": "Hono",               "intro": "src/index.ts — runs on CF Workers, Bun, Deno, Node",    "builder": _hono},
    {"id": "bun",        "label": "Bun",                "intro": "server.ts using Bun.serve() or Elysia",                  "builder": _bun},
    {"id": "deno",       "label": "Deno",               "intro": "src/server.ts using Deno.serve() or Oak",               "builder": _deno},
    # ── Python ────────────────────────────────────────────────────────────────
    {"id": "django",     "label": "Django",             "intro": "settings.py + django-csp + django-permissions-policy",   "builder": _django},
    {"id": "flask",      "label": "Flask",              "intro": "Flask app (flask-talisman)",                             "builder": _flask},
    {"id": "fastapi",    "label": "FastAPI",            "intro": "FastAPI/Starlette app entry file",                       "builder": _fastapi},
    # ── Java / JVM ────────────────────────────────────────────────────────────
    {"id": "springboot", "label": "Spring Boot",        "intro": "Spring Security configuration class",                    "builder": _spring_boot},
    # ── PHP ───────────────────────────────────────────────────────────────────
    {"id": "laravel",    "label": "Laravel",            "intro": "Artisan middleware registered in Kernel.php",            "builder": _laravel},
    # ── Ruby ──────────────────────────────────────────────────────────────────
    {"id": "rails",      "label": "Ruby on Rails",      "intro": "config/initializers/secure_headers.rb",                  "builder": _rails},
    # ── .NET ──────────────────────────────────────────────────────────────────
    {"id": "aspnet",     "label": "ASP.NET Core",       "intro": "Program.cs / Startup.cs + web.config",                  "builder": _aspnet},
    # ── Systems languages ─────────────────────────────────────────────────────
    {"id": "go",         "label": "Go (net/http)",      "intro": "A middleware function wrapping your http.Handler",       "builder": _go},
    {"id": "rust-axum",  "label": "Rust (Axum)",        "intro": "Axum 0.7 + tower-http SetResponseHeadersLayer",          "builder": _rust_axum},
    # ── Functional ────────────────────────────────────────────────────────────
    {"id": "elixir",     "label": "Elixir/Phoenix",     "intro": "lib/my_app_web/plugs/security_headers.ex + router.ex",  "builder": _elixir_phoenix},
]

PLATFORM_IDS = [str(p["id"]) for p in PLATFORMS]


def generate_fix(report: GradeReport, platform_id: str) -> str:
    """
    Generate a platform-specific config snippet adding all missing security headers.

    Args:
        report:      GradeReport from check_url().
        platform_id: One of PLATFORM_IDS (e.g. "nginx", "vercel", "nextjs").

    Returns:
        A ready-to-paste config string.

    Raises:
        ValueError: If platform_id is not recognised.
    """
    entry = next((p for p in PLATFORMS if p["id"] == platform_id), None)
    if entry is None:
        raise ValueError(
            f"Unknown platform '{platform_id}'. "
            f"Choose from: {', '.join(PLATFORM_IDS)}"
        )

    headers = _headers_to_add(report)
    if not headers:
        return (
            f"# {report.url} — no changes needed!\n"
            "# All checked security headers look good."
        )

    builder = entry["builder"]
    return builder(headers)  # type: ignore[operator,no-any-return]
