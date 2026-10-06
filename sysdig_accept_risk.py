#!/usr/bin/env python3
"""
sysdig-accept-risk -- bulk accepted-risk creation tool for Sysdig Secure.

Creates many Sysdig Secure "accepted risk" exceptions for vulnerability findings in one guided
run, instead of doing them one at a time in the Sysdig Secure UI. Always shows the exact plan
first and requires an explicit `CREATE` confirmation before writing anything.

This is a single, self-contained script (originally developed and tested as a small Python
package, then merged into one file for easy distribution -- see README.md).

Requirements: Python 3.10+, and the `requests` package (`pip install requests`).

Usage (see README.md for the full guide):
    python3 sysdig_accept_risk.py --base-url https://app.us4.sysdig.com --token-file token.txt

Pass the tenant URL you actually use in your browser -- SaaS or on-prem, any region -- the
tool figures out the matching API endpoint on its own (see `resolve_api_base_url`).
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import date
import getpass
import json
import logging
import os
import random
import re
import stat
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Optional
from urllib.parse import urlsplit, urlunsplit

import requests
import urllib3

__version__ = "0.1.0"

# ============================================================================
# Data models
# ============================================================================

class Severity(str, Enum):
    """Exact, verified severity strings used by the Sysdig vulnerability API (all lowercase)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"

    @property
    def label(self) -> str:
        return self.value.capitalize()


# Order used for display and for deciding "worst first" in summaries.
SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.NEGLIGIBLE,
]


class Source(str, Enum):
    RUNTIME = "runtime"
    REGISTRY = "registry"
    PIPELINE = "pipeline"


class Scope(str, Enum):
    GLOBAL = "global"
    IMAGE = "image"
    PACKAGE = "package"


class EntityType(str, Enum):
    """Verified `entityType` values accepted by POST .../v1beta1/accepted-risks.

    The verified API also supports image/host/policy-rule entity types that cover many CVEs in
    one unfiltered call (no severity/package filtering possible) -- this tool intentionally only
    ever creates per-CVE rules that match exactly what the user selected, so `VULNERABILITY` is
    the only entity type it constructs.
    """

    VULNERABILITY = "vulnerability"


class ContextType(str, Enum):
    """Verified `context[].contextType` values used to scope a per-CVE rule to an image
    pattern or a package/version (Host scoping is a verified, valid API option too, but this
    tool doesn't expose a Host scope, so it isn't included here).

    `IMAGE_PREFIX`/`IMAGE_SUFFIX` power the Sysdig UI's "All tags from this image" and "This
    image from all repositories and registries" presets respectively -- confirmed live
    (on-prem lab) that the API accepts and echoes back a plain fixed prefix/suffix string with
    no wildcard character in `contextValue` (the UI's `*` is just a display convention, not
    part of the stored value)."""

    IMAGE_NAME = "imageName"
    IMAGE_NAME_CONTAINS = "imageNameContains"
    IMAGE_PREFIX = "imagePrefix"
    IMAGE_SUFFIX = "imageSuffix"
    PACKAGE_NAME = "packageName"
    PACKAGE_VERSION = "packageVersion"


class ReasonType(str, Enum):
    """Verified `reason` enum values."""

    RISK_OWNED = "RiskOwned"
    RISK_TRANSFERRED = "RiskTransferred"
    RISK_AVOIDED = "RiskAvoided"
    RISK_MITIGATED = "RiskMitigated"
    RISK_NOT_RELEVANT = "RiskNotRelevant"
    CUSTOM = "Custom"

    @property
    def label(self) -> str:
        labels = {
            ReasonType.RISK_OWNED: "Risk Owned",
            ReasonType.RISK_TRANSFERRED: "Risk Transferred",
            ReasonType.RISK_AVOIDED: "Risk Avoided",
            ReasonType.RISK_MITIGATED: "Risk Mitigated",
            ReasonType.RISK_NOT_RELEVANT: "Risk Not Relevant",
            ReasonType.CUSTOM: "Custom",
        }
        return labels[self]


class StageType(str, Enum):
    """Verified `stages[]` values. All three are real, independently valid stages an
    accepted-risk rule can be scoped to -- confirmed live via the API's own 400 response,
    which lists exactly `["runtime", "pipeline", "registry"]` as the allowed values, and via
    successfully creating rules with every combination of the three."""

    PIPELINE = "pipeline"
    RUNTIME = "runtime"
    REGISTRY = "registry"


class ImageMatchKind(str, Enum):
    EXACT = "exact"
    CONTAINS = "contains"
    ALL_TAGS = "all_tags"  # fixed registry/repo/name, any tag -- UI's "All tags from this image"
    ALL_REPOS = "all_repos"  # fixed name:tag, any registry/repo -- UI's "...from all repositories and registries"


IMAGE_MATCH_TO_CONTEXT_TYPE = {
    ImageMatchKind.EXACT: ContextType.IMAGE_NAME,
    ImageMatchKind.CONTAINS: ContextType.IMAGE_NAME_CONTAINS,
    ImageMatchKind.ALL_TAGS: ContextType.IMAGE_PREFIX,
    ImageMatchKind.ALL_REPOS: ContextType.IMAGE_SUFFIX,
}


@dataclass(frozen=True)
class Finding:
    """One (CVE, affected package instance) record for a single scanned image result.

    This is the atomic unit returned by the `/v1/results/{resultId}` detail endpoint's
    `vulnerabilities` map, joined with its `packages` entry via `packageRef`. It is NOT
    guaranteed to be a globally-unique CVE -- the same CVE can appear multiple times if it
    affects multiple packages in the same image.
    """

    cve: str
    severity: Severity
    package_name: str
    package_version: str
    package_type: str
    source: Source
    result_id: str
    exploitable: bool = False
    cvss_score: Optional[float] = None
    extra: dict = field(default_factory=dict)


@dataclass(frozen=True)
class PackageGroup:
    package_name: str
    package_version: str
    findings: tuple[Finding, ...]

    @property
    def key(self) -> tuple[str, str]:
        return (self.package_name, self.package_version)


@dataclass(frozen=True)
class ContextEntry:
    context_type: ContextType
    context_value: str

    def to_json(self) -> dict:
        return {"contextType": self.context_type.value, "contextValue": self.context_value}


@dataclass(frozen=True)
class AcceptedRiskCall:
    """One exact POST body for /v1beta1/accepted-risks."""

    entity_type: EntityType
    entity_value: str
    reason: ReasonType
    description: str
    stages: tuple[StageType, ...] = ()
    context: tuple[ContextEntry, ...] = ()
    expiration_date: Optional[str] = None  # YYYY-MM-DD, or None for "Never"

    def to_json(self) -> dict:
        body: dict = {
            "entityType": self.entity_type.value,
            "entityValue": self.entity_value,
            "reason": self.reason.value,
            "description": self.description,
            "context": [c.to_json() for c in self.context],
        }
        if self.stages:
            body["stages"] = [s.value for s in self.stages]
        if self.expiration_date:
            body["expirationDate"] = self.expiration_date
        return body

    def dedupe_key(self) -> tuple:
        """Structural identity used for duplicate detection against existing accepted-risks.

        Verified live: the server's own conflict definition is
        (entityType, entityValue, context, stages) -- two rules with identical entity/context
        but DIFFERENT stages are legitimately distinct and both get created (confirmed by
        successfully creating a stage=[runtime]-only and a stage=[pipeline]-only rule for the
        same CVE with no context). `stages` must be included here, or this client-side check
        would silently skip a legitimately new rule as a false duplicate.
        """
        return (
            self.entity_type.value,
            self.entity_value,
            frozenset((c.context_type.value, c.context_value) for c in self.context),
            frozenset(s.value for s in self.stages),
        )


@dataclass
class RuleGroup:
    """A user-facing group (e.g. "10 High findings for zlib1g 1.2.13") that expands to one
    AcceptedRiskCall per covered CVE.

    `settings_summary` is a human-readable one-liner of the reason/stages/expiration used for
    this group's calls. It is tracked per-group (not just once for the whole plan) because
    Package scope lets the user pick different settings for each package/version group.
    """

    label: str
    calls: list[AcceptedRiskCall]
    covered_cves: list[str]
    settings_summary: str


@dataclass
class Plan:
    rule_groups: list[RuleGroup]
    scope: Scope
    scope_description: str

    @property
    def total_calls(self) -> int:
        return sum(len(g.calls) for g in self.rule_groups)


# ============================================================================
# Configuration and base-URL handling
# ============================================================================

class ConfigError(ValueError):
    """Raised for invalid or unsafe configuration (never includes secret material)."""


def normalize_base_url(raw: str) -> str:
    """Add a scheme if missing, drop a trailing slash, and reject a URL that already contains
    part of the API path this tool appends itself (a common copy/paste mistake).

    Accepts things like:
      - "https://app.us4.sysdig.com"
      - "app.us4.sysdig.com" (scheme added automatically)
      - "https://sysdig.customer.example.com/api" (on-prem, custom sub-path)

    This only cleans up the URL shape -- it does NOT decide which host to actually send
    requests to. See `resolve_api_base_url` for that.
    """
    if not raw or not raw.strip():
        raise ConfigError("base URL must not be empty")
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in ("https", "http"):
        raise ConfigError(f"unsupported URL scheme: {parts.scheme!r}")
    if not parts.netloc:
        raise ConfigError(f"could not find a host in {raw!r}")
    path = parts.path.rstrip("/")
    # Users overwhelmingly copy this straight out of their browser's address bar, which always
    # lives under "/secure" for both SaaS and on-prem -- strip it (and anything below it, e.g. a
    # pasted "/secure/vulnerability/..." API path someone found in devtools) back to the tenant
    # root, since this tool appends its own API sub-paths from there. Unlike "/api" below,
    # "/secure" is never itself a legitimate custom on-prem mount point, so this is always safe.
    if path == "/secure" or path.startswith("/secure/"):
        path = ""
    # Guard against a user pasting a URL that already includes part of the API path we append.
    # "/api" alone can be a legitimate custom on-prem mount point (see the docstring example
    # above), so only the more specific "/api/scanning" is rejected outright rather than stripped.
    if "/api/scanning" in path:
        raise ConfigError(
            f"base URL should not include '/api/scanning' -- pass only your tenant's console "
            f"or API root, e.g. https://app.us4.sysdig.com (got: {raw!r})"
        )
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


# Example console/browser URLs surfaced in --help / interactive prompts. Not used for
# validation -- `resolve_api_base_url` below detects the actual shape, so a region that's
# missing from this table (a new one Sysdig adds later) still works correctly.
SAAS_CONSOLE_EXAMPLES = {
    "US1": "https://secure.sysdig.com",
    "US2": "https://us2.app.sysdig.com",
    "US3": "https://app.us3.sysdig.com",
    "US4": "https://app.us4.sysdig.com",
    "EU1": "https://eu1.app.sysdig.com",
    "EU2": "https://app.eu2.sysdig.com",
    "AU1": "https://app.au1.sysdig.com",
    "IN1": "https://app.in1.sysdig.com",
}

# US1 predates the "api.<region>.sysdig.com" convention used by every other region, so it's
# mapped by exact lookup rather than the generic rule in `_api_host_for_console_host`.
_LEGACY_SAAS_API_HOSTS = {
    "secure.sysdig.com": "api.us1.sysdig.com",
    "sysdigcloud.com": "api.sysdigcloud.com",
    "app.sysdigcloud.com": "api.sysdigcloud.com",
}


def _api_host_for_console_host(host: str) -> Optional[str]:
    """Return the API hostname for a Sysdig SaaS console/browser hostname, or None if `host`
    doesn't look like a Sysdig SaaS hostname at all (the caller treats that as on-prem/custom).

    Verified against Sysdig's own regions documentation: every SaaS region's REST API is
    served from `api.<region>.sysdig.com`, e.g. `app.us4.sysdig.com` (console) pairs with
    `api.us4.sysdig.com` (API). Sysdig uses BOTH hostname orderings for the console across
    regions -- "app.<region>.sysdig.com" (US3/US4/EU2/AU1/IN1) and "<region>.app.sysdig.com"
    (US2/EU1) -- so this checks for "app" in either position rather than hardcoding one order,
    which also means a future region following either convention works without a code change.
    A bare `api.<region>.sysdig.com` (already correct) is returned unchanged, so it's always
    safe to pass either the console URL or the API URL.
    """
    host = host.lower()
    if host in _LEGACY_SAAS_API_HOSTS:
        return _LEGACY_SAAS_API_HOSTS[host]
    labels = host.split(".")
    if len(labels) != 4 or labels[-2:] != ["sysdig", "com"]:
        return None
    first, second = labels[0], labels[1]
    if first == "api":
        return host
    if first == "app" and second != "api":
        return f"api.{second}.sysdig.com"
    if second == "app" and first != "api":
        return f"api.{first}.sysdig.com"
    return None


def resolve_api_base_url(raw: str) -> tuple[str, str]:
    """Turn whatever tenant URL the user has (their browser/console URL, an on-prem URL, or --
    for anyone used to the old behavior -- an API URL directly) into the API base URL this tool
    actually needs to call, plus a short human-readable description of what was detected.

    Every Sysdig SaaS region serves its REST API from a *different* hostname than its web
    console (e.g. the console at https://app.us4.sysdig.com is served by the API at
    https://api.us4.sysdig.com) -- passing the console URL straight through silently fails,
    since they're two different upstream services. An on-prem tenant, by contrast, serves its
    UI and API from the same hostname, so any hostname that doesn't match a known SaaS shape
    is used exactly as given.
    """
    normalized = normalize_base_url(raw)
    parts = urlsplit(normalized)
    original_host = (parts.hostname or "").lower()
    api_host = _api_host_for_console_host(original_host)
    if api_host is None:
        return normalized, "on-prem or custom tenant URL -- using it exactly as given"
    netloc = api_host if not parts.port else f"{api_host}:{parts.port}"
    api_url = urlunsplit((parts.scheme, netloc, "", "", ""))
    if api_host == original_host:
        return api_url, f"already an API endpoint ({api_url}) -- using it as given"
    return api_url, f"Sysdig SaaS console URL detected -- using API endpoint {api_url}"


# ============================================================================
# Credential handling
# ============================================================================

class CredentialError(RuntimeError):
    pass


@dataclass(frozen=True)
class Credential:
    """Wraps a resolved token so it can't be accidentally f-string'd or repr'd in full."""

    _value: str
    source: str  # "env" | "file" | "prompt" | "flag" -- never the value itself

    def __repr__(self) -> str:  # pragma: no cover - defensive
        return f"Credential(source={self.source!r}, value=<redacted>)"

    __str__ = __repr__

    def header(self) -> dict:
        return {"Authorization": f"Bearer {self._value}"}

    def value(self) -> str:
        return self._value


def resolve_credential(
    token_file: Optional[str] = None,
    token_flag: Optional[str] = None,
    interactive: bool = True,
    env_var: str = "SYSDIG_SECURE_API_TOKEN",
) -> Credential:
    env_val = os.environ.get(env_var)
    if env_val:
        return Credential(env_val.strip(), source="env")

    if token_file:
        return Credential(_read_token_file(token_file), source="file")

    if interactive and sys.stdin.isatty():
        value = getpass.getpass("Sysdig Secure API token (input hidden): ").strip()
        if not value:
            raise CredentialError("no token entered")
        return Credential(value, source="prompt")

    if token_flag:
        print(
            "WARNING: --token was used; tokens passed as CLI flags can leak into shell "
            "history and process listings. Prefer SYSDIG_SECURE_API_TOKEN or --token-file.",
            file=sys.stderr,
        )
        return Credential(token_flag.strip(), source="flag")

    raise CredentialError(
        "no credential available: set SYSDIG_SECURE_API_TOKEN, pass --token-file, "
        "or run interactively so you can be prompted"
    )


def _read_token_file(path: str) -> str:
    try:
        mode = os.stat(path).st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            print(
                f"WARNING: {path!r} is readable by group/other users. "
                f"Recommend `chmod 600 {path}`.",
                file=sys.stderr,
            )
    except OSError:
        pass  # best-effort permission check only

    with open(path, "r", encoding="utf-8") as fh:
        value = fh.read().strip()
    if not value:
        raise CredentialError(f"token file {path!r} is empty")
    return value


class TokenRedactingFilter(logging.Filter):
    """Logging filter that scrubs a known secret value out of every record, defense in depth
    on top of the code simply never intending to log it in the first place."""

    def __init__(self, secret_provider) -> None:
        super().__init__()
        self._secret_provider = secret_provider

    def filter(self, record: logging.LogRecord) -> bool:
        secret = self._secret_provider()
        if secret:
            record.msg = _scrub(record.msg, secret)
            if record.args:
                record.args = tuple(_scrub(a, secret) for a in record.args)
        return True


def _scrub(value, secret: str):
    if isinstance(value, str) and secret in value:
        return value.replace(secret, "***REDACTED***")
    return value


# ============================================================================
# Logging and audit log
# ============================================================================

def configure_logging(level: int = logging.INFO, credential: Optional[Credential] = None) -> logging.Logger:
    logger = logging.getLogger("sysdig_accepted_risk")
    logger.setLevel(level)
    logger.handlers.clear()

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    if credential is not None:
        handler.addFilter(TokenRedactingFilter(credential.value))
    logger.addHandler(handler)
    return logger


class AuditLog:
    """Append-only JSON-lines audit log for accepted-risk write attempts."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        action: str,
        entity_type: str,
        entity_value: str,
        result: str,
        api_id: Optional[str] = None,
        http_status: Optional[int] = None,
        error_message: Optional[str] = None,
        extra: Optional[dict[str, Any]] = None,
    ) -> None:
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "action": action,
            "entityType": entity_type,
            "entityValue": entity_value,
            "result": result,
            "apiId": api_id,
            "httpStatus": http_status,
            "errorMessage": error_message,
            "extra": extra or {},
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")


# ============================================================================
# HTTP client (retries, pagination, TLS/proxy)
# ============================================================================

logger = logging.getLogger("sysdig_accepted_risk.http")

MAX_LIMIT = 1000
RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class ApiError(RuntimeError):
    def __init__(self, message: str, error_type: str, status_code: Optional[int]):
        super().__init__(message)
        self.message = message
        self.error_type = error_type
        self.status_code = status_code

    def __str__(self) -> str:
        return f"[{self.status_code}] {self.error_type}: {self.message}"


class HttpClient:
    def __init__(
        self,
        base_url: str,
        credential: Credential,
        tls_verify: bool = True,
        ca_bundle: Optional[str] = None,
        insecure_skip_tls_verify: bool = False,
        proxy: Optional[str] = None,
        connect_timeout: float = 10.0,
        read_timeout: float = 30.0,
        max_retries: int = 5,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._credential = credential
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.max_retries = max_retries
        self.session = session or requests.Session()

        if insecure_skip_tls_verify:
            self.session.verify = False
            # The user already explicitly opted into this via --insecure-skip-tls-verify
            # (labeled DANGEROUS in --help) -- repeating that warning on every single request
            # is just noise at that point, not new information.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        elif ca_bundle:
            self.session.verify = ca_bundle
        else:
            self.session.verify = tls_verify

        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def close(self) -> None:
        """Release pooled connections. Safe to call multiple times."""
        self.session.close()

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *_exc_info) -> None:
        self.close()

    def _timeout(self) -> tuple[float, float]:
        return (self.connect_timeout, self.read_timeout)

    def _headers(self) -> dict:
        return {**self._credential.header(), "Accept": "application/json"}

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _raise_for_error(self, response: requests.Response) -> None:
        if response.ok:
            return
        message, error_type = response.text, "unknown_error"
        try:
            body = response.json()
            message = body.get("message", message)
            error_type = body.get("type", error_type)
        except ValueError:
            pass
        raise ApiError(message=message, error_type=error_type, status_code=response.status_code)

    def _parse_json(self, response: requests.Response) -> dict:
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError as exc:
            # A 2xx response that isn't valid JSON usually means something other than the
            # Sysdig API answered (a proxy, load balancer, or captive-portal login page) --
            # surface that instead of letting a bare JSONDecodeError reach the user.
            raise ApiError(
                f"the server returned a successful response that wasn't valid JSON -- a proxy "
                f"or load balancer between you and the tenant may be intercepting the request. "
                f"First 200 chars of body: {response.text[:200]!r}",
                "invalid_json_response",
                response.status_code,
            ) from exc

    def get(self, path: str, params: Optional[dict] = None) -> dict:
        return self._request_with_retry("GET", path, params=params)

    def post(self, path: str, json_body: dict) -> dict:
        return self._request_write("POST", path, json_body=json_body)

    # -- internal --------------------------------------------------------

    def _request_with_retry(self, method: str, path: str, params: Optional[dict] = None) -> dict:
        attempt = 0
        while True:
            attempt += 1
            try:
                response = self.session.request(
                    method,
                    self._url(path),
                    params=params,
                    headers=self._headers(),
                    timeout=self._timeout(),
                )
            except requests.Timeout as exc:
                # A timeout can be one slow attempt -- worth retrying with backoff.
                if attempt > self.max_retries:
                    raise ApiError(
                        self._connection_error_message(exc), "connection_error", None
                    ) from exc
                self._sleep_backoff(attempt, None)
                continue
            except requests.ConnectionError as exc:
                # Everything else here (TLS/certificate failure, proxy unreachable, DNS
                # failure, connection refused) is deterministic given the current config --
                # retrying the identical request would just fail the same way every time, and
                # doing that 5x with exponential backoff turned a fast, clear error into what
                # looked like the tool hanging for a minute. Fail immediately instead.
                raise ApiError(
                    self._connection_error_message(exc), "connection_error", None
                ) from exc

            if response.status_code in RETRYABLE_STATUS and attempt <= self.max_retries:
                self._sleep_backoff(attempt, response.headers.get("Retry-After"))
                continue

            self._raise_for_error(response)
            return self._parse_json(response)

    def _request_write(self, method: str, path: str, json_body: Optional[dict]) -> dict:
        attempt = 0
        while True:
            attempt += 1
            try:
                response = self.session.request(
                    method,
                    self._url(path),
                    json=json_body,
                    headers=self._headers(),
                    timeout=self._timeout(),
                )
            except requests.Timeout as exc:
                # No response was received at all -- safe to retry a write, since it may never
                # have reached the server. Bounded by max_retries either way.
                if attempt > self.max_retries:
                    raise ApiError(
                        self._connection_error_message(exc), "connection_error", None
                    ) from exc
                self._sleep_backoff(attempt, None)
                continue
            except requests.ConnectionError as exc:
                # Deterministic given the current config (bad cert, unreachable proxy, DNS,
                # refused) -- see the matching comment in _request_with_retry. Fail fast.
                raise ApiError(
                    self._connection_error_message(exc), "connection_error", None
                ) from exc

            # A response WAS received -- never blind-retry a write past this point, even on 5xx.
            self._raise_for_error(response)
            return self._parse_json(response)

    def _connection_error_message(self, exc: Exception) -> str:
        """Give the most specific explanation this exception type supports, instead of one
        generic "failed to connect" for every possible cause -- timeouts, TLS/certificate
        problems, proxy failures, and DNS failures all need a different fix from the user."""
        if isinstance(exc, requests.Timeout):
            return (
                f"Timed out connecting to {self.base_url}. The tenant may be slow to respond, "
                f"or a firewall/proxy may be silently dropping the connection. "
                f"Details: {exc}"
            )
        if isinstance(exc, requests.exceptions.SSLError):
            return (
                f"TLS/certificate verification failed for {self.base_url}. If this is an "
                f"on-prem tenant with an internal certificate authority, pass --ca-bundle "
                f"pointing at that CA's certificate file. If you just want to get past this "
                f"for lab/troubleshooting purposes, --insecure-skip-tls-verify skips "
                f"certificate verification entirely (not recommended otherwise). "
                f"Details: {exc}"
            )
        if isinstance(exc, requests.exceptions.ProxyError):
            return (
                f"Could not reach the proxy configured via --proxy (or the HTTP_PROXY/"
                f"HTTPS_PROXY environment variables). Check that address is correct and "
                f"reachable. Details: {exc}"
            )
        text = str(exc)
        if any(
            marker in text
            for marker in ("Name or service not known", "nodename nor servname", "getaddrinfo failed")
        ):
            return (
                f"Could not resolve the hostname in {self.base_url} -- double-check --base-url "
                f"for typos (wrong region?) and that this machine has DNS access to it. "
                f"Details: {exc}"
            )
        return (
            f"Could not reach {self.base_url} (connection failed). Check --base-url, VPN/"
            f"firewall rules, and --proxy settings if you're behind one. Details: {exc}"
        )

    def _sleep_backoff(self, attempt: int, retry_after_header: Optional[str]) -> None:
        if retry_after_header:
            try:
                delay = float(retry_after_header)
            except ValueError:
                delay = min(2**attempt, 30)
        else:
            delay = min(2**attempt, 30)
        delay += random.uniform(0, 0.5)  # jitter
        logger.debug("retrying after %.1fs (attempt %d)", delay, attempt)
        time.sleep(delay)

    def paginate(
        self, path: str, params: Optional[dict] = None, first_page: Optional[dict] = None
    ) -> Iterator[dict]:
        """Yield every item in `data` across all pages, following `page.next` to exhaustion.

        `first_page` lets a caller that already fetched page 1 for another reason (e.g. an API
        version probe) hand that response in directly instead of this method re-fetching it --
        avoiding a redundant request against the exact same URL+params.
        """
        base_params = dict(params or {})
        base_params.setdefault("limit", MAX_LIMIT)
        cursor: Optional[str] = None
        seen_pages = 0
        body: Optional[dict] = first_page
        while True:
            if body is None:
                request_params = dict(base_params)
                if cursor:
                    request_params["cursor"] = cursor
                body = self.get(path, params=request_params)
            for item in body.get("data", []):
                yield item
            seen_pages += 1
            page = body.get("page", {})
            cursor = page.get("next") or None
            body = None
            if not cursor:
                return
            if seen_pages > 100_000:  # sanity guard against a pathological infinite cursor loop
                raise ApiError(
                    "pagination did not terminate after 100000 pages -- aborting to avoid an "
                    "unbounded loop; results may be incomplete",
                    "pagination_error",
                    None,
                )


# ============================================================================
# API version auto-detection (v1 vs v1beta1, for on-prem)
# ============================================================================

DEFAULT_CANDIDATES: tuple[str, ...] = ("v1", "v1beta1")


@dataclass
class VersionProbe:
    client: HttpClient
    probe_suffix: str
    candidates: tuple[str, ...] = DEFAULT_CANDIDATES
    _resolved: Optional[str] = field(default=None, init=False, repr=False)

    def resolve(self) -> str:
        if self._resolved:
            return self._resolved
        last_error: Optional[ApiError] = None
        for candidate in self.candidates:
            path = f"/secure/vulnerability/{candidate}{self.probe_suffix}"
            try:
                self.client.get(path, params={"limit": 1})
            except ApiError as exc:
                if exc.status_code == 404:
                    last_error = exc
                    continue
                raise
            else:
                self._resolved = candidate
                return candidate
        raise ApiError(
            f"none of the candidate API versions {self.candidates} responded for "
            f"{self.probe_suffix!r} -- this tenant may not support this API yet",
            "version_probe_failed",
            404,
        ) from last_error

    def build(self, suffix: str) -> str:
        return f"/secure/vulnerability/{self.resolve()}{suffix}"

    def resolve_with_response(self, params: dict) -> tuple[str, dict]:
        """Resolve the version using the caller's real request params, returning the actual
        response body from whichever candidate succeeded. This lets a paginated caller treat
        the resolution request as page 1 of real data instead of throwing it away and having
        `HttpClient.paginate` immediately re-fetch the exact same first page."""
        if self._resolved:
            path = f"/secure/vulnerability/{self._resolved}{self.probe_suffix}"
            return self._resolved, self.client.get(path, params=params)
        last_error: Optional[ApiError] = None
        for candidate in self.candidates:
            path = f"/secure/vulnerability/{candidate}{self.probe_suffix}"
            try:
                body = self.client.get(path, params=params)
            except ApiError as exc:
                if exc.status_code == 404:
                    last_error = exc
                    continue
                raise
            else:
                self._resolved = candidate
                return candidate, body
        raise ApiError(
            f"none of the candidate API versions {self.candidates} responded for "
            f"{self.probe_suffix!r} -- this tenant may not support this API yet",
            "version_probe_failed",
            404,
        ) from last_error


# ============================================================================
# Vulnerability results API (runtime/registry/pipeline)
# ============================================================================

_LIST_SUFFIX = {
    Source.RUNTIME: "/runtime-results",
    Source.REGISTRY: "/registry-results",
    Source.PIPELINE: "/pipeline-results",
}


@dataclass(frozen=True)
class ResultRecord:
    result_id: str
    image_id: str
    display_name: str
    source: Source
    vuln_total_by_severity: dict[str, int]
    raw: dict


def strip_digest_prefix(image_id: str) -> str:
    """freeText search does not match a literal "sha256:" prefix -- verified live."""
    return image_id.split(":", 1)[1] if ":" in image_id else image_id


_IMAGE_ID_RE = re.compile(r"^(sha256:)?[0-9a-fA-F]{64}$")


def normalize_image_id(raw: str) -> Optional[str]:
    """Returns the bare 64-hex-char digest if `raw` is a well-formed Image ID (the exact
    `imageId` shown in the Sysdig UI/results list -- `sha256:<64 hex chars>` or just the 64 hex
    chars alone), else `None`.

    Deliberately strict: partial/truncated IDs and name/tag substrings are NOT accepted here
    (unlike an earlier version of this tool) -- a stray, too-short input like "1" was found to
    silently substring-match a real image via the API's permissive `freeText` filter instead of
    failing loudly, which is confusing and, with multiple real images in a tenant, unsafe."""
    candidate = raw.strip()
    if not _IMAGE_ID_RE.match(candidate):
        return None
    return strip_digest_prefix(candidate)


class VulnerabilityResultsApi:
    def __init__(self, client: HttpClient) -> None:
        self.client = client
        # Each source gets its own version probe -- NOT one shared probe via runtime-results --
        # so that a caller who only has read access to (or only selected) registry/pipeline
        # results never needs to touch the runtime-results endpoint at all. The detail endpoint
        # for a given result reuses whichever source's probe found that result, since a result
        # detail is always fetched in the context of a specific source.
        self._probes: dict[Source, VersionProbe] = {
            source: VersionProbe(client, suffix) for source, suffix in _LIST_SUFFIX.items()
        }

    def _list_path(self, source: Source) -> str:
        return self._probes[source].build(_LIST_SUFFIX[source])

    def _detail_path(self, source: Source, result_id: str) -> str:
        return self._probes[source].build(f"/results/{result_id}")

    def list_results(self, source: Source, free_text: Optional[str] = None) -> Iterator[ResultRecord]:
        params: dict = {"limit": 1000}
        if free_text:
            params["filter"] = f'freeText in ("{free_text}")'
        probe = self._probes[source]
        # Resolve the version using this exact request (not a throwaway probe), so the
        # resolution call doubles as page 1 instead of being fetched twice.
        version, first_page = probe.resolve_with_response(params)
        path = f"/secure/vulnerability/{version}{_LIST_SUFFIX[source]}"
        for item in self.client.paginate(path, params=params, first_page=first_page):
            yield _normalize_list_item(item, source)

    def get_result_detail(self, source: Source, result_id: str) -> dict:
        return self.client.get(self._detail_path(source, result_id))


def _normalize_list_item(item: dict, source: Source) -> ResultRecord:
    image_id = item.get("imageId") or item.get("resourceId") or ""
    display_name = item.get("pullString") or item.get("mainAssetName") or ""
    return ResultRecord(
        result_id=item["resultId"],
        image_id=image_id,
        display_name=display_name,
        source=source,
        vuln_total_by_severity=item.get("vulnTotalBySeverity", {}),
        raw=item,
    )


def findings_from_detail(detail: dict, source: Source, result_id: str) -> list[Finding]:
    """Flatten a `/results/{id}` detail body into (CVE, affected package instance) Findings."""
    packages = detail.get("packages", {})
    vulnerabilities = detail.get("vulnerabilities", {})
    findings: list[Finding] = []
    for vuln in vulnerabilities.values():
        package = packages.get(vuln.get("packageRef", ""))
        if package is None:
            continue
        severity_raw = vuln.get("severity", "")
        try:
            severity = Severity(severity_raw)
        except ValueError:
            # Unrecognized severity string -- surface loudly rather than silently dropping or
            # miscategorizing a finding the API returned.
            raise ValueError(
                f"unrecognized severity {severity_raw!r} for CVE {vuln.get('name')!r}; "
                f"expected one of {[s.value for s in Severity]}"
            )
        cvss = vuln.get("cvssScore") or {}
        findings.append(
            Finding(
                cve=vuln["name"],
                severity=severity,
                package_name=package.get("name", ""),
                package_version=package.get("version", ""),
                package_type=package.get("type", ""),
                source=source,
                result_id=result_id,
                exploitable=bool(vuln.get("exploitable", False)),
                cvss_score=cvss.get("score"),
                extra={"raw_vuln": vuln, "raw_package": package},
            )
        )
    return findings


# ============================================================================
# Accepted-risks API (list, create)
# ============================================================================

_PATH = "/secure/vulnerability/v1beta1/accepted-risks"

# Verified live: unlike the vulnerability-results endpoints (which cap `limit` at 1000), this
# endpoint caps at 200 -- confirmed via a 400 response ("number must be at most 200") when the
# generic 1000 default was used. Set explicitly here rather than relying on HttpClient's default.
_MAX_LIMIT = 200


class AcceptedRisksApi:
    def __init__(self, client: HttpClient) -> None:
        self.client = client

    def list_all(self) -> Iterator[dict]:
        """Page through every existing accepted-risk record. Used for duplicate detection --
        there is no verified server-side exact filter to narrow this, so it's a full scan."""
        yield from self.client.paginate(_PATH, params={"limit": _MAX_LIMIT})

    def create(self, call: AcceptedRiskCall) -> dict:
        return self.client.post(_PATH, call.to_json())


def dedupe_key_from_raw(item: dict) -> tuple:
    """Same structural-identity key as `AcceptedRiskCall.dedupe_key()`, built from a raw
    accepted-risk API response so live results and planned calls can be compared directly.
    Must include `stages` -- verified live that two rules with identical entity/context but
    different stages are distinct, non-conflicting rules, not duplicates of each other."""
    context = item.get("context") or []
    stages = item.get("stages") or []
    return (
        item.get("entityType"),
        item.get("entityValue"),
        frozenset((c.get("contextType"), c.get("contextValue")) for c in context),
        frozenset(stages),
    )


def existing_active_dedupe_keys(items: Iterator[dict]) -> set[tuple]:
    return {dedupe_key_from_raw(item) for item in items if item.get("status") == "active"}


# ============================================================================
# Planner (severity/package filtering, rule building, dedup)
# ============================================================================

class PlannerError(ValueError):
    """Raised for a selection/scope combination the verified API does not support, with an
    explanation of *why* so the CLI can show it directly to the user instead of a stack trace."""


@dataclass(frozen=True)
class ScopeSettings:
    scope: Scope
    reason: ReasonType
    description: str
    stages: tuple[StageType, ...]
    expiration_date: Optional[str] = None
    image_match_kind: Optional[ImageMatchKind] = None
    image_match_value: Optional[str] = None


def group_by_package(findings: list[Finding]) -> list[PackageGroup]:
    buckets: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for f in findings:
        buckets[(f.package_name, f.package_version)].append(f)
    return [
        PackageGroup(package_name=k[0], package_version=k[1], findings=tuple(v))
        for k, v in buckets.items()
    ]


def filter_by_severity(findings: list[Finding], severities: set[Severity]) -> list[Finding]:
    return [f for f in findings if f.severity in severities]


def count_by_severity(findings: list[Finding]) -> dict[Severity, int]:
    counts: dict[Severity, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def validate_scope_settings(settings: ScopeSettings) -> None:
    if settings.scope == Scope.IMAGE and not settings.image_match_value:
        raise PlannerError("Image scope requires an image name or pattern.")
    if settings.scope != Scope.IMAGE and settings.image_match_value:
        raise PlannerError(
            f"Image matcher was set but scope is {settings.scope.value!r}; the verified API does "
            f"not support combining an image matcher with Global or Package scope in one call."
        )


def _context_for_group(settings: ScopeSettings, group: Optional[PackageGroup]) -> tuple[ContextEntry, ...]:
    if settings.scope == Scope.GLOBAL:
        return ()
    if settings.scope == Scope.IMAGE:
        context_type = IMAGE_MATCH_TO_CONTEXT_TYPE[settings.image_match_kind]
        return (ContextEntry(context_type, settings.image_match_value),)
    if settings.scope == Scope.PACKAGE:
        assert group is not None
        entries = [ContextEntry(ContextType.PACKAGE_NAME, group.package_name)]
        if group.package_version:
            entries.append(ContextEntry(ContextType.PACKAGE_VERSION, group.package_version))
        return tuple(entries)
    raise AssertionError(f"unhandled scope {settings.scope!r}")


def build_plan(groups: list[PackageGroup], settings: ScopeSettings) -> Plan:
    """Filtered/per-CVE plan, shared across all groups by one `settings`."""
    validate_scope_settings(settings)
    rule_groups = [_rule_group_for(group, settings) for group in groups]
    _dedupe_cross_group_calls(rule_groups)
    return Plan(rule_groups=rule_groups, scope=settings.scope, scope_description=_describe_scope(settings))


def build_plan_per_group(group_settings_pairs: list[tuple[PackageGroup, ScopeSettings]]) -> Plan:
    """Package-scope flow where the user picks (possibly different) settings for each
    package/version group in turn, per the brief's "repeat scope/settings for each remaining
    group" requirement."""
    rule_groups = []
    scopes = set()
    for group, settings in group_settings_pairs:
        validate_scope_settings(settings)
        scopes.add(settings.scope)
        rule_groups.append(_rule_group_for(group, settings))
    _dedupe_cross_group_calls(rule_groups)
    scope = scopes.pop() if len(scopes) == 1 else Scope.PACKAGE
    scope_description = "Package (per-group settings -- see each rule-group below)"
    return Plan(rule_groups=rule_groups, scope=scope, scope_description=scope_description)


def _dedupe_cross_group_calls(rule_groups: list[RuleGroup]) -> None:
    """Collapse calls that are structurally identical across DIFFERENT rule-groups in the same
    plan (mutates in place).

    This happens whenever a scope's context doesn't distinguish packages (Global: no context at
    all; Image: only an image matcher) and the *same CVE* affects more than one selected
    package/version group -- e.g. a CVE listed under both `openssl` and `openssl-libs`, or two
    versions of `glibc`. Without this step the plan would contain two byte-for-byte identical
    `entityType=vulnerability` calls; the first create would succeed and the second would fail
    live with a real 409 ("conflicting riskacceptance definition ... already exists") -- found
    during live validation, not something a schema-level check alone would catch. Package scope
    is naturally immune since its context always includes the package name, so the same CVE in
    two different groups still produces two distinct calls there.
    """
    seen: set[tuple] = set()
    for group in rule_groups:
        deduped: list[AcceptedRiskCall] = []
        omitted_cves: list[str] = []
        for call in group.calls:
            key = call.dedupe_key()
            if key in seen:
                omitted_cves.append(call.entity_value)
                continue
            seen.add(key)
            deduped.append(call)
        group.calls = deduped
        if omitted_cves:
            group.label += (
                f" [{len(omitted_cves)} CVE(s) also affect another selected group and are "
                f"already covered by that group's rule(s), not duplicated here: "
                f"{', '.join(omitted_cves)}]"
            )


def _rule_group_for(group: PackageGroup, settings: ScopeSettings) -> RuleGroup:
    cves = sorted({f.cve for f in group.findings})
    context = _context_for_group(settings, group)
    calls = [
        AcceptedRiskCall(
            entity_type=EntityType.VULNERABILITY,
            entity_value=cve,
            reason=settings.reason,
            description=settings.description,
            stages=settings.stages,
            context=context,
            expiration_date=settings.expiration_date,
        )
        for cve in cves
    ]
    severities = sorted({f.severity.label for f in group.findings})
    # "for" is only accurate when the rule is actually restricted to this package (Package
    # scope) -- for Global/Image scope the package/version was just how these CVEs were picked,
    # not something the resulting rule knows about, so "for" would wrongly imply a restriction
    # that doesn't exist.
    verb = "for" if settings.scope == Scope.PACKAGE else "selected via"
    label = (
        f"{len(cves)} CVEs ({', '.join(severities)}) {verb} "
        f"{group.package_name} {group.package_version}"
    )
    return RuleGroup(
        label=label,
        calls=calls,
        covered_cves=cves,
        settings_summary=_settings_summary(settings),
    )


def _settings_summary(settings: ScopeSettings) -> str:
    stages = ", ".join(s.value.capitalize() for s in settings.stages) or "All stages (no restriction)"
    expiration = settings.expiration_date or "Never"
    return f"Reason: {settings.reason.label} | Stages: {stages} | Expires: {expiration}"


def _describe_scope(settings: ScopeSettings) -> str:
    if settings.scope == Scope.GLOBAL:
        return "Global (each CVE accepted everywhere)"
    if settings.scope == Scope.IMAGE:
        return f"Image ({settings.image_match_kind.value}: '{settings.image_match_value}')"
    if settings.scope == Scope.PACKAGE:
        return "Package (scoped per selected package/version group)"
    raise AssertionError(f"unhandled scope {settings.scope!r}")


PACKAGE_SCOPE_NOTICE = (
    "Package scope covers one package/version group's CVEs per set of rules. Every CVE still "
    "requires its own accepted-risk API call -- selecting N package/version groups with a total "
    "of M matching CVEs creates M rules across N rule-groups, never one rule per group."
)


@dataclass(frozen=True)
class ClassifiedCall:
    call: AcceptedRiskCall
    rule_group_label: str
    is_duplicate: bool


def classify_calls(plan: Plan, existing_keys: set[tuple]) -> list[ClassifiedCall]:
    """Mark each planned call as new or an already-existing active duplicate, using a full
    pre-fetch of existing accepted-risks (see `api.accepted_risks.existing_active_dedupe_keys`)."""
    out: list[ClassifiedCall] = []
    for group in plan.rule_groups:
        for call in group.calls:
            out.append(
                ClassifiedCall(
                    call=call,
                    rule_group_label=group.label,
                    is_duplicate=call.dedupe_key() in existing_keys,
                )
            )
    return out


# ============================================================================
# Report rendering (dry-run text, JSON report)
# ============================================================================

def render_dry_run(plan: Plan, classified: list[ClassifiedCall]) -> str:
    lines: list[str] = ["You are about to create accepted risks for:", "", f"Scope: {plan.scope_description}", ""]
    for group in plan.rule_groups:
        lines.append(f"  - {group.label}")
        lines.append(f"      {group.settings_summary}  ({len(group.calls)} API call(s))")
    lines.append("")

    new_calls = [c for c in classified if not c.is_duplicate]
    dup_calls = [c for c in classified if c.is_duplicate]
    lines.append(f"Planned accepted-risk rule-groups: {len(plan.rule_groups)}")
    lines.append(
        f"Planned accepted-risk API calls: {len(classified)} total "
        f"({len(new_calls)} new, {len(dup_calls)} already exist as active rules and will be "
        f"skipped as duplicates)"
    )
    lines.append(
        "  Note: the program considers a rule a duplicate if its CVE, scope (\"Where\"), and "
        "stage(s) exactly match an existing active rule -- reason, description, and "
        "expiration don't matter. So seeing the same CVE elsewhere isn't enough on its own; "
        "the scope and stage(s) have to match exactly too."
    )
    if plan.scope in (Scope.GLOBAL, Scope.IMAGE):
        lines.append(
            "  Note: the CVE(s) above were selected via the package/version shown, but this "
            "rule's actual scope is the one shown above (\"Scope: ...\"). Once created, it "
            "accepts each CVE under that scope regardless of which package it came from."
        )
    lines.append("")
    lines.append("No changes have been made. Type CREATE to continue.")
    return "\n".join(lines)


@dataclass
class CallResult:
    call: AcceptedRiskCall
    rule_group_label: str
    outcome: str  # "created" | "skipped_duplicate" | "failed"
    api_id: Optional[str] = None
    http_status: Optional[int] = None
    error_message: Optional[str] = None
    remediation: Optional[str] = None


def build_json_report(plan: Plan, results: list[CallResult]) -> dict:
    return {
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scope": plan.scope.value,
        "scopeDescription": plan.scope_description,
        "summary": {
            "attempted": len(results),
            "created": sum(1 for r in results if r.outcome == "created"),
            "skippedDuplicate": sum(1 for r in results if r.outcome == "skipped_duplicate"),
            "failed": sum(1 for r in results if r.outcome == "failed"),
        },
        "ruleGroups": [
            {
                "label": g.label,
                "coveredCves": g.covered_cves,
                "settingsSummary": g.settings_summary,
            }
            for g in plan.rule_groups
        ],
        "results": [
            {
                "entityType": r.call.entity_type.value,
                "entityValue": r.call.entity_value,
                "context": [c.to_json() for c in r.call.context],
                "ruleGroup": r.rule_group_label,
                "outcome": r.outcome,
                "apiId": r.api_id,
                "httpStatus": r.http_status,
                "errorMessage": r.error_message,
                "remediation": r.remediation,
            }
            for r in results
        ],
    }


def write_json_report(path: str, report: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")


def render_human_summary(report: dict) -> str:
    s = report["summary"]
    lines = [
        f"Accepted-risk creation report ({report['generatedAt']})",
        f"Scope: {report['scopeDescription']}",
        "",
        f"Attempted: {s['attempted']}   Created: {s['created']}   "
        f"Skipped (duplicate): {s['skippedDuplicate']}   Failed: {s['failed']}",
        "",
    ]
    failed = [r for r in report["results"] if r["outcome"] == "failed"]
    if failed:
        lines.append("Failures:")
        for r in failed:
            lines.append(
                f"  - {r['entityType']}={r['entityValue']} ({r['ruleGroup']}): "
                f"[{r['httpStatus']}] {r['errorMessage']}"
            )
            if r["remediation"]:
                lines.append(f"      remediation: {r['remediation']}")
    return "\n".join(lines)


# ============================================================================
# Interactive guided workflow
# ============================================================================


class WorkflowCancelled(Exception):
    """Raised to unwind the guided workflow with a user-facing message, no writes made."""


class Prompter:
    """Thin wrapper over input()/print(); tests substitute a scripted subclass."""

    def text(self, prompt: str, default: Optional[str] = None) -> str:
        suffix = f" [{default}]" if default else ""
        raw = input(f"{prompt}{suffix}: ").strip()
        return raw or (default or "")

    def choice(self, prompt: str, options: list[str]) -> str:
        while True:
            print(prompt)
            for i, opt in enumerate(options, 1):
                print(f"  {i}) {opt}")
            raw = input("> ").strip()
            if raw.isdigit() and 1 <= int(raw) <= len(options):
                return options[int(raw) - 1]
            print("Invalid selection, try again.")

    def multi_choice(self, prompt: str, options: list[str]) -> list[str]:
        print(prompt)
        for i, opt in enumerate(options, 1):
            print(f"  {i}) {opt}")
        print("Enter comma-separated numbers, or 'all'.")
        while True:
            raw = input("> ").strip()
            if raw.lower() == "all":
                return list(options)
            try:
                idxs = [int(x) for x in raw.split(",") if x.strip()]
            except ValueError:
                idxs = []
            if idxs and all(1 <= i <= len(options) for i in idxs):
                return [options[i - 1] for i in idxs]
            print("Invalid selection, try again.")

    def yes_no(self, prompt: str, default: bool = False) -> bool:
        suffix = "Y/n" if default else "y/N"
        raw = input(f"{prompt} [{suffix}]: ").strip().lower()
        if not raw:
            return default
        return raw in ("y", "yes")

    def confirm_create(self) -> bool:
        raw = input("Type CREATE to continue, anything else to cancel.\n> ").strip()
        return raw == "CREATE"


# -- Step 1: connectivity ------------------------------------------------


def validate_connectivity(client: HttpClient) -> None:
    """A harmless authenticated read, per the brief, before continuing any further."""
    client.get(_PATH, params={"limit": 1})


# -- Step 3: image lookup -------------------------------------------------


def _collect_image_id(prompter: Prompter) -> str:
    """Loops until the user provides a well-formed Image ID. Deliberately strict -- no
    partial/truncated IDs and no name/tag substring search -- since a stray, unrelated input
    (e.g. a leftover "1" typed for a previous prompt) was found to silently substring-match a
    real image via the API's permissive `freeText` filter instead of failing loudly. There's no
    ambiguity risk from a "latest"-style tag or a differently-versioned same-named image either,
    since an Image ID uniquely identifies one exact scanned image."""
    while True:
        raw = prompter.text("Image ID (the exact sha256 digest shown in Sysdig's results list)")
        normalized = normalize_image_id(raw)
        if normalized is not None:
            return normalized
        print(
            f"{raw!r} isn't a valid Image ID -- expected the 64-character sha256 digest shown "
            f"in the Sysdig UI/results list, optionally prefixed with 'sha256:'. Try again."
        )


def find_image(
    vr_api: VulnerabilityResultsApi,
    sources: list[Source],
    image_id_search: str,
    prompter: Prompter,
) -> tuple[str, dict[Source, ResultRecord]]:
    """Search each selected source for the exact Image ID `image_id_search` (already validated
    and normalized to a bare 64-hex-char digest by `_collect_image_id`/`normalize_image_id`
    before this is ever called -- no partial IDs, no name/tag substrings). Passed to the API's
    `freeText` filter, whose hits are trusted directly as candidates rather than re-filtered,
    since a full unique sha256 digest can't meaningfully collide with anything else.

    Deliberately does NOT support searching by the separate registry/manifest "Digest" value
    some Sysdig UI pages show for an image (`metadata.digest` in a result's detail) -- verified
    live that `freeText` never matches against it, only against `imageId`/`pullString`, and
    those are two genuinely different sha256 values for the same image. There's no known API
    filter for the manifest digest, so this is a real, permanent limitation, not a bug to fix
    here -- callers must pass the Image ID.

    Disambiguates multiple matches per the brief; never silently picks one."""
    candidates: dict[Source, list[ResultRecord]] = {}
    for source in sources:
        candidates[source] = list(vr_api.list_results(source, free_text=image_id_search))

    all_image_ids = sorted({r.image_id for recs in candidates.values() for r in recs})
    if not all_image_ids:
        raise WorkflowCancelled(
            f"No image found with Image ID '{image_id_search}' in the selected source(s) "
            f"(searched all pages). If you pasted a 'Digest' value from the Sysdig UI, that's "
            f"a different value and won't match; use the Image ID instead."
        )

    if len(all_image_ids) == 1:
        chosen_image_id = all_image_ids[0]
    else:
        labeled = []
        for image_id in all_image_ids:
            names = sorted({r.display_name for recs in candidates.values() for r in recs if r.image_id == image_id})
            shown = ", ".join(names[:3]) + ("..." if len(names) > 3 else "")
            labeled.append(f"{image_id}  ({shown})")
        chosen_label = prompter.choice(
            "Multiple images matched -- choose one (only non-sensitive identifying info shown):",
            labeled,
        )
        chosen_image_id = all_image_ids[labeled.index(chosen_label)]

    chosen_by_source: dict[Source, ResultRecord] = {}
    for source, recs in candidates.items():
        same = [r for r in recs if r.image_id == chosen_image_id]
        if not same:
            continue
        if len(same) == 1:
            chosen_by_source[source] = same[0]
        else:
            labeled = [f"{r.display_name} (resultId={r.result_id})" for r in same]
            chosen_label = prompter.choice(
                f"Multiple {source.value} results reference this image digest -- choose one:",
                labeled,
            )
            chosen_by_source[source] = same[labeled.index(chosen_label)]
    return chosen_image_id, chosen_by_source


# -- Step 4/5: findings, severities, package groups -----------------------


def collect_findings(vr_api: VulnerabilityResultsApi, chosen_by_source: dict[Source, ResultRecord]) -> list[Finding]:
    findings: list[Finding] = []
    for source, record in chosen_by_source.items():
        detail = vr_api.get_result_detail(source, record.result_id)
        findings.extend(findings_from_detail(detail, source, record.result_id))
    return findings


def select_severities(findings: list[Finding], prompter: Prompter) -> set[Severity]:
    counts = count_by_severity(findings)
    present = [s for s in SEVERITY_ORDER if counts.get(s, 0) > 0]
    if not present:
        raise WorkflowCancelled("No findings on this image for the selected source(s).")
    print(
        "Findings by severity for this image "
        "(count = CVE x affected-package instances for this scan, not unique CVEs):"
    )
    for s in present:
        print(f"  {s.label}: {counts[s]}")
    options = [f"{s.label} ({counts[s]})" for s in present]
    chosen_labels = prompter.multi_choice("Select one or more severities:", options)
    return {present[options.index(label)] for label in chosen_labels}


def select_groups(findings: list[Finding], severities: set[Severity], prompter: Prompter) -> list[PackageGroup]:
    filtered = filter_by_severity(findings, severities)
    groups = group_by_package(filtered)
    groups.sort(key=lambda g: (-len(g.findings), g.package_name, g.package_version))
    if not groups:
        raise WorkflowCancelled("No findings match the selected severities.")
    options = [
        f"{g.package_name} {g.package_version} -- {len(g.findings)} findings "
        f"({len({f.cve for f in g.findings})} unique CVEs)"
        for g in groups
    ]
    chosen_labels = prompter.multi_choice(
        "Select one or more package/version groups (selections are OR'd together):", options
    )
    chosen = [groups[options.index(label)] for label in chosen_labels]
    print("\nResulting groups:")
    for g in chosen:
        print(f"  - {g.package_name} {g.package_version}: {len({f.cve for f in g.findings})} unique CVEs")
    return chosen


# -- Step 6: scope + settings ---------------------------------------------

# Verified live: the API's own 400 response lists exactly these three as the allowed `stages[]`
# values, and every combination of them (alone or together) was successfully created. All
# three stages a rule can be scoped to -- a checkbox-style multi-select, since with 3 stages
# there are 7 meaningful non-empty combinations, too many for a flat single-choice list.
_STAGE_CHECKBOX_OPTIONS = ["Pipeline", "Runtime", "Registry"]
_STAGE_VALUE_FOR_LABEL = {
    "Pipeline": StageType.PIPELINE,
    "Runtime": StageType.RUNTIME,
    "Registry": StageType.REGISTRY,
}


def _collect_stages(prompter: Prompter) -> tuple[StageType, ...]:
    """Ask which stage(s) a rule applies to.

    An empty/omitted `stages` array is its own distinct, verified-live "no restriction" state
    (matches Sysdig's own Terraform provider examples, e.g. `stages = []`) -- not the same
    thing as explicitly listing all three known stages, which would stop meaning "no
    restriction" if Sysdig ever adds a fourth stage. So "all stages" is asked as its own
    yes/no first, before offering the individual stages as checkboxes.
    """
    if prompter.yes_no("Apply to all stages (no restriction)?", default=True):
        return ()
    chosen = prompter.multi_choice("Stage(s) this rule applies to:", _STAGE_CHECKBOX_OPTIONS)
    return tuple(_STAGE_VALUE_FOR_LABEL[label] for label in chosen)


def _collect_common_settings(prompter: Prompter, scope: Scope) -> tuple[ReasonType, tuple[StageType, ...], Optional[str]]:
    reason_label = prompter.choice("Reason:", [r.label for r in ReasonType])
    reason = next(r for r in ReasonType if r.label == reason_label)

    stages = _collect_stages(prompter)

    never_expires = prompter.yes_no("Never expires?", default=True)
    expiration_date = None if never_expires else _collect_expiration_date(prompter)
    return reason, stages, expiration_date


def _collect_expiration_date(prompter: Prompter) -> str:
    while True:
        raw = prompter.text("Expiration date (YYYY-MM-DD)")
        try:
            date.fromisoformat(raw)
        except ValueError:
            print(f"{raw!r} isn't a valid date in YYYY-MM-DD form, try again.")
            continue
        return raw


_IMAGE_CONTAINS_LABEL = "Image name contains specified value"


def _split_image_prefix_suffix(pull_string: str) -> tuple[Optional[str], Optional[str]]:
    """Split a resolved pull string into the two values the UI's wildcard presets need:
    `prefix` is "registry/repo/name" plus its `:`/`@` boundary, no tag/digest (for "All tags
    from this image"); `suffix` is the leading "/" plus everything after it -- `/name[:tag]
    [@digest]` (for "This image from all repositories and registries").

    Either value is `None` if that preset wouldn't add any real matching power over an exact
    match for this particular pull string, AND (not just "or") lacks a safe boundary character
    to anchor on -- these two conditions always coincide here, since the boundary character
    IS the thing being wildcarded away:
    - `prefix` is `None` if there's no `:`/`@` in the name (no tag/digest to genericize --
      "All tags" would return the exact same string as "This image", with no `:`/`@` anchor
      protecting it from a same-prefix collision like "harbor-db" vs "harbor-db2").
    - `suffix` is `None` if there's no "/" in the pull string (no registry/repo to genericize
      -- confirmed live with a real image, `cli-scanner-node-demo:1.0`: offering "All repos"
      there would produce a bare, anchor-less value that could false-positive match an
      unrelated image merely ending in the same text, e.g. "sebas-cli-scanner-node-demo:1.0").

    When present, both values keep their boundary character (`prefix` ends in `:`/`@`,
    `suffix` starts with `/`) for the same anchoring reason -- confirmed live that the Sysdig
    UI itself renders an existing rule's suffix as `"*" + contextValue` verbatim (no separator
    inserted), so the leading "/" has to be part of the stored value itself, not just the
    picker's preview text."""
    repo_path, sep, tail = pull_string.rpartition("/")
    delimiter_positions = [i for i in (tail.find(":"), tail.find("@")) if i != -1]
    if delimiter_positions:
        boundary = min(delimiter_positions) + 1
        name_with_boundary = tail[:boundary]
        prefix = f"{repo_path}/{name_with_boundary}" if repo_path else name_with_boundary
    else:
        prefix = None
    suffix = f"{sep}{tail}" if sep else None
    return prefix, suffix


def _collect_image_match(prompter: Prompter, image_hints: list[str]) -> tuple[ImageMatchKind, str]:
    """Ask which image(s) an Image-scoped rule should cover.

    `image_hints` are the actual pull-string(s) of the image the user already searched for and
    confirmed earlier in this same run. Defaulting to that (as its own explicit "this image"
    choice, matching the Sysdig UI's own "This Image" option) matters because that's
    overwhelmingly the common case -- asking the user to blind-retype a name/pattern from
    scratch, with no reminder of what they already found, was easy to get wrong.

    Offers up to four image-match shapes the Sysdig UI itself exposes for "Where: Image": "This
    Image" (exact), "This image from all repositories and registries" (any registry/repo, this
    name+tag -- `imageSuffix`), "All tags from this image" (this registry/repo/name, any tag --
    `imagePrefix`), and "Image name contains specified value". The prefix/suffix values are
    computed automatically from the already-found pull string, never free-typed -- confirmed
    live that the API wants the plain fixed substring with no wildcard character, matching how
    the UI's own `*` in "*/harbor-db:v2.15.1" / "docker.io/goharbor/harbor-db:*" is just a
    display convention.

    The "all repos" and "all tags" presets are each only offered when they'd actually mean
    something for this specific pull string -- see `_split_image_prefix_suffix` for exactly
    when that's not the case (e.g. no "/" in the name at all, like `cli-scanner-node-demo:1.0`
    -- confirmed live that offering "all repos" there would produce an anchor-less value that
    could false-positive match an unrelated image).
    """
    if image_hints:
        this_image_options = [f"This image: {name}" for name in image_hints]

        all_tags_by_label: dict[str, str] = {}
        all_repos_by_label: dict[str, str] = {}
        for name in image_hints:
            prefix, suffix = _split_image_prefix_suffix(name)
            if prefix is not None:
                all_tags_by_label.setdefault(f"All tags from this image ({prefix}*)", prefix)
            if suffix is not None:
                all_repos_by_label.setdefault(
                    f"This image from all repositories and registries (*{suffix})", suffix
                )

        options = (
            this_image_options
            + list(all_repos_by_label)
            + list(all_tags_by_label)
            + [_IMAGE_CONTAINS_LABEL]
        )
        chosen = prompter.choice("Which image(s) should this rule cover?", options)
        if chosen in this_image_options:
            return ImageMatchKind.EXACT, image_hints[this_image_options.index(chosen)]
        if chosen in all_repos_by_label:
            return ImageMatchKind.ALL_REPOS, all_repos_by_label[chosen]
        if chosen in all_tags_by_label:
            return ImageMatchKind.ALL_TAGS, all_tags_by_label[chosen]
        value = prompter.text("Image name contains")
        return ImageMatchKind.CONTAINS, value
    if prompter.yes_no("Match any image whose name contains a value, instead of an exact name?"):
        return ImageMatchKind.CONTAINS, prompter.text("Image name contains")
    return ImageMatchKind.EXACT, prompter.text("Image name")


def collect_scope_and_plan(groups: list[PackageGroup], prompter: Prompter, image_hints: list[str] = ()):
    print(
        "Where should this rule apply? Package restricts it to the package/version you just "
        "selected; Global/Image do not -- they'll accept the CVE regardless of package."
    )
    scope_label = prompter.choice("Where/scope:", ["Global", "Image", "Package"])
    scope = Scope(scope_label.lower())

    if scope == Scope.IMAGE:
        match_kind, match_value = _collect_image_match(prompter, list(image_hints))
        reason, stages, expiration_date = _collect_common_settings(prompter, scope)
        description = prompter.text("Description", default="Accepted risk")
        settings = ScopeSettings(
            scope=scope,
            reason=reason,
            description=description,
            stages=stages,
            expiration_date=expiration_date,
            image_match_kind=match_kind,
            image_match_value=match_value,
        )
        return build_plan(groups, settings)

    if scope == Scope.GLOBAL:
        reason, stages, expiration_date = _collect_common_settings(prompter, scope)
        description = prompter.text("Description", default="Accepted risk")
        settings = ScopeSettings(
            scope=scope, reason=reason, description=description, stages=stages,
            expiration_date=expiration_date,
        )
        return build_plan(groups, settings)

    # Package scope: repeat scope/settings selection for each remaining group, per the brief.
    # Each group gets its own settings, and after each one the tool explicitly names whichever
    # groups are still pending, so it's never ambiguous what's left to configure.
    if len(groups) > 1:
        print(f"\n{PACKAGE_SCOPE_NOTICE}\n")
    pairs = []
    for index, group in enumerate(groups, start=1):
        remaining = groups[index:]  # groups after this one, not yet configured
        print(
            f"\n--- ({index} of {len(groups)}) Settings for "
            f"{group.package_name} {group.package_version} ---"
        )
        reason, stages, expiration_date = _collect_common_settings(prompter, scope)
        description = prompter.text(
            "Description",
            default=f"Accepted risk for {group.package_name} {group.package_version}",
        )
        settings = ScopeSettings(
            scope=scope, reason=reason, description=description, stages=stages,
            expiration_date=expiration_date,
        )
        pairs.append((group, settings))
        if remaining:
            still_missing = ", ".join(f"{g.package_name} {g.package_version}" for g in remaining)
            print(f"\nStill missing settings for: {still_missing}")
        else:
            print("\nAll package/version groups now have settings configured.")
    return build_plan_per_group(pairs)


# -- Step 8: execution -----------------------------------------------------


@dataclass
class ExecutionOptions:
    concurrency: int = 3


def execute_plan(
    ar_api: AcceptedRisksApi,
    classified: list[ClassifiedCall],
    audit_log: AuditLog,
    options: ExecutionOptions,
) -> list[CallResult]:
    """Create every non-duplicate call with bounded concurrency. Duplicates are recorded as
    skipped, never re-sent. A create that fails is reported with a sanitized error and does not
    stop the remaining, independent calls."""
    results: list[CallResult] = []

    for c in classified:
        if c.is_duplicate:
            results.append(
                CallResult(call=c.call, rule_group_label=c.rule_group_label, outcome="skipped_duplicate")
            )
            audit_log.record(
                action="create_accepted_risk",
                entity_type=c.call.entity_type.value,
                entity_value=c.call.entity_value,
                result="skipped_duplicate",
            )

    to_create = [c for c in classified if not c.is_duplicate]

    def _create(c: ClassifiedCall) -> CallResult:
        try:
            response = ar_api.create(c.call)
            return CallResult(
                call=c.call,
                rule_group_label=c.rule_group_label,
                outcome="created",
                api_id=response.get("id"),
            )
        except ApiError as exc:
            return CallResult(
                call=c.call,
                rule_group_label=c.rule_group_label,
                outcome="failed",
                http_status=exc.status_code,
                error_message=exc.message,
                remediation=_remediation_for(exc),
            )

    with ThreadPoolExecutor(max_workers=max(1, options.concurrency)) as pool:
        futures = {pool.submit(_create, c): c for c in to_create}
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            audit_log.record(
                action="create_accepted_risk",
                entity_type=result.call.entity_type.value,
                entity_value=result.call.entity_value,
                result=result.outcome,
                api_id=result.api_id,
                http_status=result.http_status,
                error_message=result.error_message,
            )
    return results


def _remediation_for(exc: ApiError) -> str:
    if exc.status_code == 400:
        return "Check that the entity/context/reason/stage combination matches a verified schema; see README."
    if exc.status_code == 401 or exc.status_code == 403:
        return "Check that the credential has permission to create accepted risks in this tenant."
    if exc.status_code == 404:
        return "The tenant/base URL or API version path may be wrong for this on-prem/SaaS instance."
    if exc.status_code == 409:
        return (
            "This exact rule (same entity/context/reason/stage) already exists in the tenant. "
            "This tool's own duplicate check should normally catch this before attempting the "
            "call -- re-running the tool is safe either way."
        )
    if exc.status_code == 429:
        return "Rate-limited; re-running the tool will safely skip already-created rules and retry the rest."
    if exc.status_code and exc.status_code >= 500:
        return "Server-side error; re-running the tool later will safely skip already-created rules."
    return "See error message above."


# ============================================================================
# Command-line interface / entry point
# ============================================================================

# Fixed, already-tested-safe defaults for the transport knobs a customer never needs to tune.
_CONNECT_TIMEOUT = 10.0
_READ_TIMEOUT = 30.0
_MAX_RETRIES = 5
_CONCURRENCY = 3


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sysdig-accept-risk",
        description="Interactively create Sysdig Secure accepted-risk rules from runtime, "
        "registry, and pipeline vulnerability findings. Always shows the full plan and asks "
        "you to type CREATE before changing anything.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument(
        "--base-url",
        help="The tenant URL you use in your browser to open Sysdig -- SaaS (any region) or "
        f"on-prem, e.g. {SAAS_CONSOLE_EXAMPLES['US4']}. The matching API endpoint is detected "
        "automatically.",
    )
    parser.add_argument(
        "--token-file",
        help="Path to a file containing just your API token (recommended over typing it "
        "each time)",
    )
    parser.add_argument(
        "--token", help="Your API token directly (discouraged -- visible in shell history)"
    )
    parser.add_argument(
        "--ca-bundle", help="Path to a custom CA certificate file, for on-prem tenants with an "
        "internal certificate authority"
    )
    parser.add_argument(
        "--insecure-skip-tls-verify",
        action="store_true",
        help="DANGEROUS: disable TLS certificate verification (lab/troubleshooting only)",
    )
    parser.add_argument(
        "--proxy", help="HTTP(S) proxy URL, if your network requires one to reach Sysdig"
    )
    parser.add_argument(
        "--report-dir", default="./reports",
        help="Where to save the report after creating rules (default: ./reports)",
    )
    return parser


def _validate_transport_args(args: argparse.Namespace) -> None:
    if args.insecure_skip_tls_verify and args.ca_bundle:
        raise ConfigError("--insecure-skip-tls-verify and --ca-bundle are mutually exclusive")


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        _validate_transport_args(args)
        return _run_interactive(args)
    except WorkflowCancelled as exc:
        print(f"\nCancelled: {exc}", file=sys.stderr)
        return 1
    except (CredentialError, ApiError, ValueError) as exc:
        # ConfigError and PlannerError are ValueError subclasses, so this also covers them.
        print(f"\nError: {exc}", file=sys.stderr)
        if isinstance(exc, ApiError):
            print(f"  {_remediation_for(exc)}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled by user. No changes were made.", file=sys.stderr)
        return 130
    except EOFError:
        # stdin closed/ran out before a prompt was answered. No write can have happened yet --
        # every prompt in the guided workflow comes before the dry-run/confirm step, and the
        # confirm step itself only proceeds on the literal string "CREATE".
        print("\nInput ended before the workflow finished. No changes were made.", file=sys.stderr)
        return 1
    except Exception as exc:  # last resort: never show a bare traceback to the user
        log_path = _write_crash_log(args, exc)
        print(f"\nUnexpected error: {type(exc).__name__}: {exc}", file=sys.stderr)
        print(
            f"This isn't one of the errors this tool anticipates. Full technical details were "
            f"saved to {log_path} -- share that file (never your token) with your Sysdig "
            f"contact if this keeps happening.",
            file=sys.stderr,
        )
        return 1


def _write_crash_log(args: argparse.Namespace, exc: BaseException) -> str:
    report_dir = getattr(args, "report_dir", None) or "./reports"
    path = Path(report_dir) / "error.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(f"--- {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} ---\n")
        fh.write(traceback.format_exc())
        fh.write("\n")
    return str(path)


def _build_client(args: argparse.Namespace, base_url: str) -> HttpClient:
    credential = resolve_credential(token_file=args.token_file, token_flag=args.token)
    configure_logging(credential=credential)
    api_base_url, detection_message = resolve_api_base_url(base_url)
    print(detection_message)
    client = HttpClient(
        base_url=api_base_url,
        credential=credential,
        ca_bundle=args.ca_bundle,
        insecure_skip_tls_verify=args.insecure_skip_tls_verify,
        proxy=args.proxy,
        connect_timeout=_CONNECT_TIMEOUT,
        read_timeout=_READ_TIMEOUT,
        max_retries=_MAX_RETRIES,
    )
    print(f"Validating connectivity to {client.base_url} ...")
    validate_connectivity(client)
    print("Connected.\n")
    return client


def _run_interactive(args: argparse.Namespace) -> int:
    prompter = Prompter()
    print("Sysdig Secure bulk accepted-risk tool\n")

    base_url = args.base_url
    if not base_url:
        example = SAAS_CONSOLE_EXAMPLES["US4"]
        while not base_url:
            base_url = prompter.text(
                "Tenant URL (the one you use in your browser, e.g. "
                f"{example} -- SaaS, any region, or on-prem)"
            )
    with _build_client(args, base_url) as client:
        vr_api = VulnerabilityResultsApi(client)
        ar_api = AcceptedRisksApi(client)

        source_labels = prompter.multi_choice(
            "Vulnerability result source(s):", [s.value.capitalize() for s in Source]
        )
        sources = [Source(label.lower()) for label in source_labels]

        image_id_search = _collect_image_id(prompter)
        image_id, chosen_by_source = find_image(vr_api, sources, image_id_search, prompter)
        print(f"\nConfirmed image: {image_id}\n")
        image_hints = sorted({r.display_name for r in chosen_by_source.values() if r.display_name})

        findings = collect_findings(vr_api, chosen_by_source)
        severities = select_severities(findings, prompter)
        groups = select_groups(findings, severities, prompter)

        plan = collect_scope_and_plan(groups, prompter, image_hints)

        print("\nChecking for existing accepted-risks to avoid duplicates...")
        existing_keys = existing_active_dedupe_keys(ar_api.list_all())
        print(f"Found {len(existing_keys)} existing active accepted-risk rule(s) in this tenant.")
        classified = classify_calls(plan, existing_keys)

        print()
        print(render_dry_run(plan, classified))

        if not prompter.confirm_create():
            print("Cancelled. No changes have been made.")
            return 0

        audit_log = AuditLog(f"{args.report_dir}/audit.jsonl")
        results = execute_plan(ar_api, classified, audit_log, ExecutionOptions(concurrency=_CONCURRENCY))

        report = build_json_report(plan, results)
        report_path = f"{args.report_dir}/report.json"
        write_json_report(report_path, report)
        print()
        print(render_human_summary(report))
        print(f"\nFull JSON report written to {report_path}")
        return 0 if report["summary"]["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
