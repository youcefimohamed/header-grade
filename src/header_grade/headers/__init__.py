"""Security header checker modules."""

from .base import BaseHeaderChecker
from .cache_control import CacheControlChecker
from .coep import COEPChecker
from .cookies import CookieChecker
from .coop import COOPChecker
from .corp import CORPChecker
from .cors import CORSChecker
from .csp import CSPChecker
from .deprecated_headers import DeprecatedHeadersChecker
from .hsts import HSTSChecker
from .info_disclosure import InfoDisclosureChecker
from .origin_agent_cluster import OriginAgentClusterChecker
from .permissions import PermissionsPolicyChecker
from .referrer import ReferrerPolicyChecker
from .reporting_endpoints import ReportingEndpointsChecker
from .x_content_type import XContentTypeChecker
from .x_frame import XFrameChecker
from .x_permitted_cross_domain import XPermittedCrossDomainPoliciesChecker
from .xss_protection import XSSProtectionChecker

ALL_CHECKERS: list[type[BaseHeaderChecker]] = [
    # ── Core security headers (critical impact) ───────────────────────────────
    CSPChecker,
    HSTSChecker,
    XFrameChecker,
    XContentTypeChecker,
    ReferrerPolicyChecker,
    PermissionsPolicyChecker,
    # ── Cross-origin isolation ────────────────────────────────────────────────
    COOPChecker,
    COEPChecker,
    CORPChecker,
    OriginAgentClusterChecker,
    # ── Cookie security ───────────────────────────────────────────────────────
    CookieChecker,
    # ── CORS misconfiguration ─────────────────────────────────────────────────
    CORSChecker,
    # ── Caching ───────────────────────────────────────────────────────────────
    CacheControlChecker,
    # ── Plugin cross-domain policy ────────────────────────────────────────────
    XPermittedCrossDomainPoliciesChecker,
    # ── Violation reporting (RFC 9512, Feb 2024) ──────────────────────────────
    ReportingEndpointsChecker,
    # ── Info disclosure ───────────────────────────────────────────────────────
    InfoDisclosureChecker,
    # ── Deprecated / dangerous headers present ────────────────────────────────
    DeprecatedHeadersChecker,
    # ── Deprecated header that should be absent or set to 0 ──────────────────
    XSSProtectionChecker,
]

__all__ = [
    "BaseHeaderChecker",
    "ALL_CHECKERS",
    "CSPChecker",
    "HSTSChecker",
    "XFrameChecker",
    "XContentTypeChecker",
    "ReferrerPolicyChecker",
    "PermissionsPolicyChecker",
    "COOPChecker",
    "COEPChecker",
    "CORPChecker",
    "OriginAgentClusterChecker",
    "CookieChecker",
    "CORSChecker",
    "CacheControlChecker",
    "XPermittedCrossDomainPoliciesChecker",
    "ReportingEndpointsChecker",
    "InfoDisclosureChecker",
    "DeprecatedHeadersChecker",
    "XSSProtectionChecker",
]
