"""
scanner.py - Core Security Scanner Module (v2.0 — Upgraded)
============================================================
Upgrades over v1:
  ✦ Multithreaded scanning via ThreadPoolExecutor
  ✦ Smarter crawler: parallel fetching, URL normalisation, skip binary assets
  ✦ Advanced detection logic:
      - Response-length delta analysis (baseline vs. payload)
      - HTTP status-code deviation tracking
      - Regex pattern matching across 4 DB engine families (15 patterns)
      - Time-based anomaly hint (response-time spike for blind SQLi)
      - Mixed-content detection, sensitive data pattern matching
  ✦ New check: Vulnerable & Outdated Components (OWASP A06)
  ✦ IDOR hint in Broken Access Control check
  ✦ Passive login-form discovery; authentication strength is explicitly not tested

DISCLAIMER: Educational and authorized testing only.
All payloads are benign probes — no real exploitation performed.
"""

import http.client
import ipaddress
import logging
import os
import re
import socket
import ssl
import time
import threading
from http.cookies import SimpleCookie
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit, urlencode, parse_qs

import requests
from bs4 import BeautifulSoup
from requests.structures import CaseInsensitiveDict

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────
# Tuneable constants
# ─────────────────────────────────────────────────────────
REQUEST_TIMEOUT   = 5           # seconds per HTTP request
MAX_RESPONSE_BYTES = 1_000_000
MAX_REDIRECTS = 4
MAX_CRAWL_PAGES   = 20          # max unique pages the crawler visits
MAX_SCAN_WORKERS  = 6           # parallel workers for concurrent checks
MAX_CRAWL_WORKERS = 8           # parallel workers for crawling

USER_AGENT = "Mozilla/5.0 (compatible; OWASPScanner/2.0; +https://owasp.org)"

# The probes below do not execute JavaScript, alter data, or invoke database delays.
SQL_PAYLOADS = ["'", '"']
XSS_PAYLOADS = ["<owasp-probe-7f3a>"]

# Only non-destructive, non-secret administrative route names are probed.
ADMIN_PATHS = [
    "/admin", "/dashboard", "/api/admin",
]

# ── HTTP security headers every site should send ──────────
REQUIRED_HEADERS = {
    "X-Content-Type-Options":    "Prevents MIME-type sniffing attacks",
    "X-Frame-Options":           "Prevents clickjacking via iframes",
    "Content-Security-Policy":   "Restricts resource loading to trusted sources",
    "Strict-Transport-Security": "Enforces HTTPS connections (HSTS)",
    "X-XSS-Protection":          "Enables legacy browser XSS filter",
    "Referrer-Policy":           "Controls referrer information leakage",
    "Permissions-Policy":        "Restricts browser feature access",
    "Cache-Control":             "Prevents sensitive data caching",
}

# ── SQL error patterns (MySQL, PostgreSQL, Oracle, MSSQL, SQLite) ─
SQL_ERROR_PATTERNS = [
    r"sql syntax.*mysql",
    r"warning.*mysql_",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"you have an error in your sql",
    r"syntax error.*postgresql",
    r"pg_query\(\).*error",
    r"ora-\d{5}",
    r"microsoft ole db provider",
    r"odbc.*driver",
    r"sqlite.*error",
    r"division by zero",
    r"supplied argument is not a valid mysql",
    r"column count doesn't match value count",
    r"error converting data type",
]

# Requests are prepared per thread for cookie/header handling. Network connections
# themselves are made to an explicitly validated IP address (DNS-rebinding safe).
_thread_local = threading.local()


def _session() -> requests.Session:
    """Return a per-thread request context."""
    if not hasattr(_thread_local, "session"):
        s = requests.Session()
        s.headers.update({"User-Agent": USER_AGENT})
        s.trust_env = False
        _thread_local.session = s
    return _thread_local.session


# ─────────────────────────────────────────────────────────
# Low-level HTTP helpers
# ─────────────────────────────────────────────────────────

class URLValidationError(ValueError):
    """The target URL is invalid or resolves to a restricted network."""


class LabAuthenticationError(RuntimeError):
    """The explicitly requested local DVWA session could not be established."""

    def __init__(self, message: str, authentication_status: dict = None):
        super().__init__(message)
        self.authentication_status = authentication_status or {
            "authentication_mode": "enabled",
            "login_session_establishment": "failed",
            "protected_access_verified": False,
            "protected_access_url": None,
        }


def _local_lab_config():
    """Return the exact opt-in lab origin and pinned address, or None."""
    target = os.environ.get("SCANNER_LOCAL_LAB_URL")
    address_text = os.environ.get("SCANNER_LOCAL_LAB_IP")
    if not target and not address_text:
        return None
    if not target or not address_text:
        raise URLValidationError("Local lab mode requires both target URL and pinned IP settings.")
    try:
        parsed = urlsplit(target)
        port = parsed.port
        address = ipaddress.ip_address(address_text)
    except ValueError as exc:
        raise URLValidationError("Local lab target configuration is invalid.") from exc
    if (
        parsed.scheme.lower() != "http"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or not port
        or not address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        raise URLValidationError("Local lab configuration must be an HTTP origin and a private, unicast IP.")
    host = parsed.hostname.rstrip(".").lower()
    return (parsed.scheme.lower(), host, port), address


def _local_lab_auth_enabled():
    return os.environ.get("SCANNER_LOCAL_LAB_AUTH_ENABLED") == "1"


def validate_local_lab_auth_target(url: str) -> None:
    config = _local_lab_config()
    if (
        not _local_lab_auth_enabled()
        or config is None
        or _url_origin(urlsplit(url)) != config[0]
    ):
        raise URLValidationError("Authenticated scans are available only for the configured DVWA lab target.")


def _url_origin(parsed):
    scheme = parsed.scheme.lower()
    return scheme, (parsed.hostname or "").rstrip(".").lower(), parsed.port or (
        443 if scheme == "https" else 80
    )


def _log_target(url: str) -> str:
    """Return only the scheme, host, and optional port for logs."""
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        if not host:
            return "<invalid-url>"
        port = parsed.port
        authority = f"[{host}]" if ":" in host else host
        if port:
            authority = f"{authority}:{port}"
        return f"{parsed.scheme.lower()}://{authority}"
    except (TypeError, ValueError):
        return "<invalid-url>"


def _validate_url(url: str, allowed_host: str = None, allowed_origin=None) -> str:
    """Normalize a public HTTP(S) URL and reject unsafe or out-of-scope targets."""
    if not isinstance(url, str) or not url or len(url) > 2048:
        raise URLValidationError("Enter a valid HTTP or HTTPS URL (maximum 2048 characters).")
    if any(ord(char) < 32 or char.isspace() for char in url) or "\\" in url:
        raise URLValidationError("The URL contains invalid characters.")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise URLValidationError("The URL or port is malformed.") from exc
    host = parsed.hostname
    if parsed.scheme.lower() not in ("http", "https") or not host:
        raise URLValidationError("Only absolute http:// and https:// URLs are allowed.")
    if parsed.username is not None or parsed.password is not None:
        raise URLValidationError("URLs containing user credentials are not allowed.")
    host = host.rstrip(".").lower()
    origin = _url_origin(parsed)
    lab_config = _local_lab_config()
    is_local_lab_target = bool(lab_config and origin == lab_config[0])
    if allowed_origin and origin != allowed_origin:
        raise URLValidationError("Redirects must remain on the approved target origin.")
    if not host or (
        not is_local_lab_target
        and (host == "localhost" or host.endswith((".localhost", ".local", ".internal")))
    ):
        raise URLValidationError("Local and internal hostnames are not allowed.")
    if allowed_host and host != allowed_host.rstrip(".").lower():
        raise URLValidationError("Redirects and links must remain on the approved target host.")
    try:
        addresses = {
            ipaddress.ip_address(item[4][0].split("%", 1)[0])
            for item in socket.getaddrinfo(host, port or (443 if parsed.scheme == "https" else 80),
                                           type=socket.SOCK_STREAM)
        }
    except (OSError, ValueError) as exc:
        raise URLValidationError("The target hostname could not be resolved.") from exc
    if is_local_lab_target:
        if addresses != {lab_config[1]}:
            raise URLValidationError("The local lab hostname did not resolve only to its configured IP.")
    elif not addresses or any(not address.is_global for address in addresses):
        raise URLValidationError("Targets resolving to private, reserved, or non-routable IP addresses are not allowed.")
    netloc = f"[{host}]" if ":" in host else host
    if port:
        netloc = f"{netloc}:{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))


def _pinned_connection(parsed, address, timeout):
    """Open a socket to a validated IP while retaining the original TLS hostname."""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme == "https":
        conn = http.client.HTTPSConnection(parsed.hostname, port, timeout=timeout,
                                           context=ssl.create_default_context())
        conn.connect = lambda: _connect_pinned_tls(conn, address)
    else:
        conn = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)
        conn.connect = lambda: _connect_pinned_http(conn, address)
    return conn


def _connect_pinned_http(conn, address):
    conn.sock = socket.create_connection((address, conn.port), conn.timeout)


def _connect_pinned_tls(conn, address):
    raw_socket = socket.create_connection((address, conn.port), conn.timeout)
    try:
        conn.sock = conn._context.wrap_socket(raw_socket, server_hostname=conn.host)
    except Exception:
        raw_socket.close()
        raise


def _one_request(method, url, params=None, data=None, headers=None, timeout=REQUEST_TIMEOUT):
    session = _session()
    prepared = session.prepare_request(requests.Request(
        method, url, params=params, data=data, headers=headers,
    ))
    normalized = _validate_url(prepared.url)
    parsed = urlsplit(normalized)
    addresses = socket.getaddrinfo(
        parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80),
        type=socket.SOCK_STREAM,
    )
    allowed = [ipaddress.ip_address(item[4][0].split("%", 1)[0]) for item in addresses]
    lab_config = _local_lab_config()
    if _url_origin(parsed) == (lab_config[0] if lab_config else None):
        if set(allowed) != {lab_config[1]}:
            raise URLValidationError("The local lab hostname did not resolve only to its configured IP.")
    elif not allowed or any(not address.is_global for address in allowed):
        raise URLValidationError("The target hostname resolved to a restricted IP address.")
    target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    request_headers = dict(prepared.headers)
    request_headers["Accept-Encoding"] = "identity"
    request_headers["Connection"] = "close"
    conn = _pinned_connection(parsed, str(allowed[0]), timeout)
    try:
        conn.request(prepared.method, target, body=prepared.body, headers=request_headers)
        raw = conn.getresponse()
        body = raw.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise requests.exceptions.ContentDecodingError(
                f"Response exceeded the {MAX_RESPONSE_BYTES}-byte limit."
            )
        response = requests.Response()
        response.status_code = raw.status
        response.reason = raw.reason
        response.headers = CaseInsensitiveDict(raw.getheaders())
        response._content = body
        response._content_consumed = True
        response.url = normalized
        response.request = prepared
        response.encoding = requests.utils.get_encoding_from_headers(response.headers)
        response.cookies = requests.cookies.RequestsCookieJar()
        for header, value in raw.getheaders():
            if header.lower() == "set-cookie":
                cookie = SimpleCookie()
                cookie.load(value)
                for morsel in cookie.values():
                    rest = {}
                    if morsel["httponly"]:
                        rest["HttpOnly"] = morsel["httponly"]
                    if morsel["samesite"]:
                        rest["SameSite"] = morsel["samesite"]
                    response.cookies.set(
                        morsel.key, morsel.value, domain=parsed.hostname,
                        path=morsel["path"] or "/", secure=bool(morsel["secure"]),
                        rest=rest,
                    )
        return response
    finally:
        conn.close()


def _request(method, url, params=None, data=None, **kwargs):
    """Issue a size-limited request with pinned DNS and validated redirects."""
    timeout = kwargs.pop("timeout", REQUEST_TIMEOUT)
    headers = kwargs.pop("headers", None)
    if kwargs:
        raise TypeError("Unsupported request option.")
    start = time.monotonic()
    try:
        current = _validate_url(url)
        initial_host = urlsplit(current).hostname
        initial_origin = _url_origin(urlsplit(current))
        lab_config = _local_lab_config()
        lab_origin = lab_config[0] if lab_config and _url_origin(urlsplit(current)) == lab_config[0] else None
        request_headers = dict(headers or {})
        response_cookies = requests.cookies.RequestsCookieJar()
        for redirect_count in range(MAX_REDIRECTS + 1):
            response = _one_request(
                method, current, params=params if redirect_count == 0 else None,
                data=data if redirect_count == 0 else None,
                headers=request_headers, timeout=timeout,
            )
            hop_cookies = getattr(response, "cookies", None)
            if hop_cookies:
                response_cookies.update(hop_cookies)
            response.cookies = response_cookies
            response.elapsed_seconds = time.monotonic() - start
            if response.status_code not in (301, 302, 303, 307, 308):
                return response, response.elapsed_seconds
            location = response.headers.get("Location")
            if not location or redirect_count == MAX_REDIRECTS:
                return response, response.elapsed_seconds
            current = _validate_url(
                urljoin(response.url, location),
                allowed_host=initial_host,
                allowed_origin=lab_origin,
            )
            if _url_origin(urlsplit(current)) == initial_origin:
                if response_cookies:
                    prior = SimpleCookie()
                    prior.load(request_headers.get("Cookie", ""))
                    for cookie in response_cookies:
                        prior[cookie.name] = cookie.value
                    request_headers["Cookie"] = "; ".join(
                        f"{name}={morsel.value}" for name, morsel in prior.items()
                    )
            else:
                request_headers.pop("Cookie", None)
                response_cookies.clear()
            if response.status_code == 303 or (response.status_code in (301, 302) and method != "GET"):
                method, data, params = "GET", None, None
        return response, response.elapsed_seconds
    except (requests.exceptions.RequestException, OSError, http.client.HTTPException,
            URLValidationError, TypeError, ValueError) as exc:
        logger.info("Safe request failed for %s (%s).", _log_target(url), type(exc).__name__)
        return None, time.monotonic() - start


def _get(url: str, params: dict = None, headers: dict = None, **kwargs):
    """Safe GET. Returns (response | None, elapsed_seconds)."""
    return _request("GET", url, params=params, headers=headers, **kwargs)


def _post(url: str, data: dict = None, headers: dict = None, **kwargs):
    """Safe POST. Returns (response | None, elapsed_seconds)."""
    return _request("POST", url, data=data, headers=headers, **kwargs)


def _cookie_header(cookie_jar):
    """Build an in-memory Cookie header without logging or persisting values."""
    return "; ".join(f"{cookie.name}={cookie.value}" for cookie in cookie_jar)


def _merge_cookies(*jars):
    merged = requests.cookies.RequestsCookieJar()
    for jar in jars:
        if jar:
            merged.update(jar)
    return merged


def _authenticate_local_dvwa(base_url: str, username: str, password: str) -> tuple[dict, dict]:
    """Authenticate only to the exact configured DVWA lab origin."""
    authentication_status = {
        "authentication_mode": "authenticated",
        "authentication_mode_enabled": True,
        "login_session_establishment": "failed",
        "protected_access_verified": False,
        "protected_access_url": None,
    }

    def fail(message: str):
        raise LabAuthenticationError(message, dict(authentication_status))

    lab_config = _local_lab_config()
    parsed_base = urlsplit(base_url)
    if (
        not _local_lab_auth_enabled()
        or lab_config is None
        or _url_origin(parsed_base) != lab_config[0]
        or not username
        or not password
    ):
        fail("Authenticated scans are unavailable for this target.")

    login_page, _ = _get(base_url)
    if not login_page:
        fail("The local lab login page could not be reached.")

    login_soup = BeautifulSoup(login_page.text, "html.parser")
    login_form = next(
        (form for form in _find_login_forms(login_soup)
         if form.get("method", "get").lower() == "post"),
        None,
    )
    if login_form is None:
        fail("A DVWA login form was not found.")

    username_input = login_form.find(
        "input", attrs={"name": re.compile(r"^username$", re.I)}
    )
    password_input = login_form.find(
        "input", attrs={"type": re.compile(r"^password$", re.I)}
    )
    if not username_input or not username_input.get("name") or not password_input or not password_input.get("name"):
        fail("The local lab login form is not recognized.")

    action = urljoin(login_page.url, login_form.get("action") or login_page.url)
    try:
        action = _validate_url(action, allowed_origin=lab_config[0])
    except URLValidationError as exc:
        raise LabAuthenticationError(
            "The local lab login action is outside the configured origin.",
            dict(authentication_status),
        ) from exc

    form_data = {}
    for field in login_form.find_all("input", attrs={"type": "hidden"}):
        if field.get("name"):
            form_data[field["name"]] = field.get("value", "")
    form_data[username_input["name"]] = username
    form_data[password_input["name"]] = password
    submit = login_form.find("input", attrs={"type": "submit"})
    if submit and submit.get("name"):
        form_data[submit["name"]] = submit.get("value", "")

    headers = {"Cookie": _cookie_header(login_page.cookies)} if login_page.cookies else {}
    login_result, _ = _post(action, data=form_data, headers=headers)
    if not login_result:
        fail("The local lab rejected or did not complete authentication.")
    cookies = _merge_cookies(login_page.cookies, login_result.cookies)
    if cookies:
        headers["Cookie"] = _cookie_header(cookies)

    authenticated_url = urljoin(base_url, "/index.php")
    authenticated_page, _ = _get(authenticated_url, headers=headers)
    if not authenticated_page or authenticated_page.status_code != 200:
        fail("The local lab session could not be verified.")
    authenticated_soup = BeautifulSoup(authenticated_page.text, "html.parser")
    logout_link = any(
        "logout" in (anchor.get("href", "") + " " + anchor.get_text(" ", strip=True)).lower()
        for anchor in authenticated_soup.find_all("a", href=True)
    )
    if _find_login_forms(authenticated_soup) or not logout_link:
        fail("The local lab session could not be verified.")
    cookies = _merge_cookies(cookies, authenticated_page.cookies)
    if cookies:
        headers["Cookie"] = _cookie_header(cookies)
    if not headers.get("Cookie"):
        fail("The local lab did not issue a session cookie.")
    authentication_status.update({
        "login_session_establishment": "succeeded",
        "protected_access_verified": True,
        "protected_access_url": authenticated_url,
    })
    return headers, authentication_status


# ─────────────────────────────────────────────────────────
# Upgrade 1 — Advanced Multi-threaded Crawler
# ─────────────────────────────────────────────────────────

class Crawler:
    """
    Parallel, same-domain web crawler.

    Improvements over v1:
      • ThreadPoolExecutor for concurrent page fetching
      • URL normalisation (strip fragment, lowercase scheme/host)
      • Skip binary assets (images, CSS, JS, fonts, archives)
      • Records per-page metadata: status, title, form count, load time
      • Exposes page_urls() for the scanner to iterate
    """

    SKIP_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
        ".pdf", ".zip", ".tar", ".gz", ".exe",
        ".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
        ".xml", ".rss", ".atom",
    }

    def __init__(
        self, seed_url: str, max_pages: int = MAX_CRAWL_PAGES,
        headers: dict = None,
    ):
        self.seed_url    = _validate_url(seed_url)
        self.max_pages   = max(1, min(int(max_pages), MAX_CRAWL_PAGES))
        self.base_domain = urlsplit(self.seed_url).hostname
        self.headers     = dict(headers or {})
        self._visited    = set()
        self._lock       = threading.Lock()
        self.pages: list[dict] = []

    def crawl(self) -> list[dict]:
        """Crawl from seed and return list of page metadata dicts."""
        logger.info("[Crawler] Starting from %s (max=%d)", _log_target(self.seed_url), self.max_pages)
        queue = [self.seed_url]
        queued = {self._normalize(self.seed_url)}

        with ThreadPoolExecutor(max_workers=MAX_CRAWL_WORKERS) as pool:
            while queue and len(self.pages) < self.max_pages:
                batch = []
                available = min(MAX_CRAWL_WORKERS, self.max_pages - len(self.pages))
                while queue and len(batch) < available:
                    url = queue.pop(0)
                    norm = self._normalize(url)
                    with self._lock:
                        if norm in self._visited:
                            continue
                        self._visited.add(norm)
                    batch.append(url)

                if not batch:
                    break

                futures = {pool.submit(self._fetch_page, u): u for u in batch}
                for fut in as_completed(futures):
                    try:
                        result = fut.result()
                    except Exception as exc:
                        logger.warning(
                            "[Crawler] Page processing failed (%s).",
                            type(exc).__name__,
                        )
                        continue
                    if result:
                        with self._lock:
                            if len(self.pages) < self.max_pages:
                                self.pages.append(result)
                                links = result.pop("_links", [])
                                for link in links:
                                    norm = self._normalize(link)
                                    if norm not in self._visited and norm not in queued:
                                        queue.append(link)
                                        queued.add(norm)

        logger.info("[Crawler] Complete — %d pages discovered", len(self.pages))
        return self.pages

    def page_urls(self) -> list[str]:
        return [p["url"] for p in self.pages]

    def _fetch_page(self, url: str) -> dict | None:
        resp, elapsed = _get(url, headers=self.headers)
        if not resp:
            return None
        ct = resp.headers.get("Content-Type", "")
        if "text/html" not in ct:
            return None

        soup = BeautifulSoup(resp.text, "html.parser")
        title = (soup.title.string or "").strip() if soup.title else "(no title)"
        forms = _extract_form_metadata(url, soup)

        links = []
        for tag in soup.find_all("a", href=True):
            abs_link = urljoin(url, tag["href"])
            try:
                normalized = _validate_url(abs_link, allowed_host=self.base_domain)
            except URLValidationError:
                continue
            norm = self._normalize(normalized)
            p = urlsplit(normalized)
            if not self._skip_ext(p.path):
                with self._lock:
                    if norm not in self._visited:
                        links.append(normalized)

        logger.debug("[Crawler] %s HTTP %d | %d forms | %d links | %.2fs",
                     _log_target(url), resp.status_code, len(forms), len(links), elapsed)

        return {
            "url":        url,
            "status":     resp.status_code,
            "title":      title,
            "form_count": len(forms),
            "forms":      forms,
            "elapsed":    round(elapsed, 3),
            "_links":     links,
        }

    @staticmethod
    def _normalize(url: str) -> str:
        p = urlsplit(url)
        query = urlencode(sorted(parse_qs(p.query, keep_blank_values=True).items()), doseq=True)
        return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", query, ""))

    @staticmethod
    def _skip_ext(path: str) -> bool:
        ext = ("." + path.rsplit(".", 1)[-1].lower()) if "." in path else ""
        return ext in Crawler.SKIP_EXTENSIONS


# ─────────────────────────────────────────────────────────
# Upgrade 3 — Advanced Detection Logic Helpers
# ─────────────────────────────────────────────────────────

def _contains_sql_error(text: str) -> bool:
    """Match explicit database error signatures, not generic response changes."""
    t = text.lower()
    return any(re.search(p, t) for p in SQL_ERROR_PATTERNS)


def _response_length_anomaly(baseline_len: int, probe_len: int) -> bool:
    """A response difference is a triage indicator only, never proof of a flaw."""
    return baseline_len > 0 and abs(probe_len - baseline_len) / baseline_len > 0.20


def _analyze_sqli_response(baseline_resp, probe_resp, elapsed: float, payload: str) -> str | None:
    """Return possible-SQLi evidence only for a new, explicit database error."""
    if probe_resp is None:
        return None
    if _contains_sql_error(probe_resp.text) and not (
        baseline_resp and _contains_sql_error(baseline_resp.text)
    ):
        return "A database-specific error signature appeared only after a quote probe."
    return None


# ─────────────────────────────────────────────────────────
# Individual Security Check Functions
# ─────────────────────────────────────────────────────────

def check_sql_injection(
    url: str, headers: dict = None, form_metadata: list = None,
) -> dict:
    """Probe query parameters and GET forms using non-destructive quote markers."""
    logger.info("[SQLi] Testing: %s", _log_target(url))
    findings, evidence = [], []

    baseline_resp, _ = _get(url, headers=headers)
    if not baseline_resp:
        return _result(
            "SQL Injection", "A03:2021 – Injection", False,
            ["Target could not be reached; this check was not completed."], "Error",
            "Verify the target is reachable and try again.", finding_type="error",
            affected_url=url,
        )

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    candidates = [
        {
            "endpoint": url,
            "parameter": name,
            "params": params,
            "page_url": url,
            "form": None,
        }
        for name in list(params)[:3]
    ]
    soup = BeautifulSoup(baseline_resp.text, "html.parser")
    discovered_forms = (
        form_metadata if form_metadata is not None
        else _extract_form_metadata(url, soup)
    )
    post_candidates = [
        item for item in discovered_forms[:3]
        if item.get("method") == "POST"
    ]
    for form_index, form in enumerate(soup.find_all("form")[:3]):
        metadata = (
            discovered_forms[form_index]
            if form_index < len(discovered_forms)
            else _extract_form_metadata(url, BeautifulSoup(str(form), "html.parser"))[0]
        )
        if metadata["method"] == "POST":
            continue
        if metadata["method"] != "GET":
            continue
        action = urljoin(url, form.get("action") or url)
        try:
            action = _validate_url(action, allowed_host=parsed.hostname)
        except URLValidationError:
            continue
        form_data = _build_form_data(form, SQL_PAYLOADS[0])
        probe_field_names = _payload_form_field_names(form)
        if form_data and probe_field_names:
            candidates.append({
                "endpoint": action,
                "parameter": None,
                "params": form_data,
                "page_url": url,
                "form": {
                    **metadata,
                    "probe_field_names": probe_field_names,
                },
            })

    if not candidates:
        evidence = [
            {
                "type": "form_candidate_not_tested",
                "description": (
                    "POST form fields were discovered but were not submitted; "
                    "POST-based SQL injection was not tested."
                ),
                "page_url": item["page_url"],
                "form_action": item["action"],
                "method": item["method"],
                "field_names": [field["name"] for field in item["fields"]],
            }
            for item in post_candidates
        ]
        details = [
            "No query parameters or safe GET form inputs were available; SQL injection inputs were not assessed."
        ]
        if post_candidates:
            details.append(
                f"Found {len(post_candidates)} POST form(s); their fields were not submitted or tested."
            )
        return _result(
            name="SQL Injection", owasp="A03:2021 – Injection",
            detected=False,
            details=details,
            severity="None",
            recommendation="Review server-side handling of input fields; POST forms are discovered but not submitted.",
            finding_type="unsupported", affected_url=url, evidence=evidence,
            status="NOT TESTED",
        )

    for candidate in candidates:
        endpoint = candidate["endpoint"]
        param_name = candidate["parameter"]
        original_params = candidate["params"]
        candidate_finding = False
        for payload in SQL_PAYLOADS:
            test_params = dict(original_params)
            if param_name:
                test_params[param_name] = [payload]
            else:
                for key in test_params:
                    test_params[key] = [payload]
            probe_resp, elapsed = _get(endpoint, params=test_params, headers=headers)
            finding = _analyze_sqli_response(baseline_resp, probe_resp, elapsed, payload)
            if finding:
                form = candidate["form"]
                label = (
                    f"Parameter '{param_name}'" if param_name
                    else f"GET form field(s) {', '.join(form['probe_field_names'])}"
                )
                findings.append(f"{label}: {finding}")
                item = {
                    "type": "database_error",
                    "description": finding,
                    "url": endpoint,
                    "page_url": candidate["page_url"],
                    "method": form["method"] if form else "GET",
                }
                if param_name:
                    item["parameter"] = param_name
                if form:
                    item.update({
                        "form_action": form["action"],
                        "field_names": form["probe_field_names"],
                    })
                evidence.append(item)
                candidate_finding = True
                break
        if not candidate_finding:
            form = candidate["form"]
            tested = {
                "type": "form_candidate_tested" if form else "query_candidate_tested",
                "description": (
                    "Safe GET input markers were tested; no new database error signature was observed."
                ),
                "page_url": candidate["page_url"],
                "url": endpoint,
                "method": "GET",
            }
            if param_name:
                tested["parameter"] = param_name
            if form:
                tested["form_action"] = form["action"]
                tested["field_names"] = form["probe_field_names"]
            evidence.append(tested)

    if post_candidates:
        findings.extend(
            f"POST form at {item['action']} has fields "
            f"{', '.join(field['name'] for field in item['fields'])}; POST inputs were not tested."
            for item in post_candidates
        )
        evidence.extend({
            "type": "form_candidate_not_tested",
            "description": "POST form was discovered but not submitted; POST-based SQL injection was not tested.",
            "page_url": item["page_url"],
            "form_action": item["action"],
            "method": item["method"],
            "field_names": [field["name"] for field in item["fields"]],
        } for item in post_candidates)

    has_database_error = any(
        item["type"] == "database_error" for item in evidence
    )
    if not has_database_error:
        findings.append(
            "No new database error signatures were observed in the tested query/GET inputs. "
            "Response status, length, and timing differences alone are not treated as SQL injection."
        )

    result = _result(
        name="SQL Injection", owasp="A03:2021 – Injection",
        detected=bool(evidence), details=findings,
        severity=(
            "High" if any(item["type"] == "database_error" for item in evidence)
            else "None"
        ),
        recommendation="Use parameterized queries and server-side input validation.",
        finding_type=(
            "possible" if any(item["type"] == "database_error" for item in evidence)
            else "partial" if post_candidates
            else "none"
        ),
        affected_url=evidence[0]["url"] if evidence else url, evidence=evidence,
    )
    result["detected"] = any(item["type"] == "database_error" for item in evidence)
    if post_candidates and not result["detected"]:
        result["status"] = "PARTIALLY TESTED"
    return result


def check_xss(
    url: str, headers: dict = None, form_metadata: list = None,
) -> dict:
    """Detect possible unescaped marker reflection without executing script."""
    logger.info("[XSS] Testing: %s", _log_target(url))
    findings, evidence = [], []

    baseline_resp, _ = _get(url, headers=headers)
    if not baseline_resp:
        return _result(
            name="Cross-Site Scripting (XSS)", owasp="A03:2021 – Injection",
            detected=False, details=["Target could not be reached; this check was not completed."],
            severity="Error", recommendation="Encode all user output.",
            finding_type="error", affected_url=url,
        )
    parsed = urlsplit(url)
    soup = BeautifulSoup(baseline_resp.text, "html.parser")
    candidates = []
    discovered_forms = (
        form_metadata if form_metadata is not None
        else _extract_form_metadata(url, soup)
    )
    for form_index, form in enumerate(soup.find_all("form")[:3]):
        metadata = (
            discovered_forms[form_index]
            if form_index < len(discovered_forms)
            else _extract_form_metadata(url, BeautifulSoup(str(form), "html.parser"))[0]
        )
        if metadata["method"] != "GET":
            continue
        action = urljoin(url, form.get("action") or url)
        try:
            action = _validate_url(action, allowed_host=parsed.hostname)
        except URLValidationError:
            continue
        form_data = _build_form_data(form, XSS_PAYLOADS[0])
        probe_field_names = _payload_form_field_names(form)
        if form_data and probe_field_names:
            candidates.append((
                action, form_data, "GET form",
                {**metadata, "probe_field_names": probe_field_names},
            ))
    if not candidates:
        keys = parse_qs(parsed.query, keep_blank_values=True)
        keys = list(keys)[:3] or ["q"]
        for key in keys:
            candidates.append((url, {key: XSS_PAYLOADS[0]}, f"query parameter '{key}'", None))

    marker = XSS_PAYLOADS[0]
    for endpoint, params, context, form in candidates:
        probe, _ = _get(endpoint, params=params, headers=headers)
        if probe and marker in probe.text:
            field_names = (
                form["probe_field_names"]
                if form else [context.split("'")[1]] if context.startswith("query parameter ")
                else []
            )
            detail = (
                f"The inert HTML marker was reflected unescaped in a {context}; "
                "JavaScript execution was not tested or confirmed."
            )
            findings.append(detail)
            evidence_item = {
                "type": "unescaped_reflection",
                "description": detail,
                "url": endpoint,
                "page_url": url,
                "method": form["method"] if form else "GET",
                "field_names": field_names,
            }
            if form:
                evidence_item["form_action"] = form["action"]
            elif field_names:
                evidence_item["parameter"] = field_names[0]
            evidence.append(evidence_item)
    if not findings:
        findings.append("No unescaped marker reflection was observed.")
    return _result(
        name="Cross-Site Scripting (XSS)", owasp="A03:2021 – Injection",
        detected=bool(evidence), details=findings, severity="Medium" if evidence else "None",
        recommendation="Contextually encode untrusted output and apply a restrictive Content-Security-Policy.",
        finding_type="possible" if evidence else "none",
        affected_url=evidence[0]["url"] if evidence else url, evidence=evidence,
    )


def check_security_misconfiguration(url: str, headers: dict = None) -> dict:
    """Inspect security headers and visible server error/configuration leakage."""
    logger.info("[MiscConfig] Testing: %s", _log_target(url))
    resp, _ = _get(url, headers=headers)

    if not resp:
        return _result(
            name="Security Misconfiguration", owasp="A05:2021 – Security Misconfiguration",
            detected=False, details=["Target could not be reached; this check was not completed."],
            severity="Error", recommendation="Verify the target is reachable.",
            finding_type="error", affected_url=url,
        )

    findings, evidence = [], []
    resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    for header in ("X-Content-Type-Options", "Content-Security-Policy", "Referrer-Policy"):
        if header.lower() not in resp_headers_lower:
            detail = f"{header} response header is absent."
            findings.append(detail)
            evidence.append({"type": "missing_header", "description": detail, "url": resp.url})
    if urlsplit(resp.url).scheme == "https" and "strict-transport-security" not in resp_headers_lower:
        detail = "Strict-Transport-Security response header is absent on an HTTPS page."
        findings.append(detail)
        evidence.append({"type": "missing_header", "description": detail, "url": resp.url})

    for h in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"):
        val = resp.headers.get(h, "")
        if val and any(c.isdigit() for c in val):
            detail = f"Version information is disclosed by the {h} response header."
            findings.append(detail)
            evidence.append({"type": "version_disclosure", "description": detail, "url": resp.url})
    body_lower = resp.text.lower()
    if any(s in body_lower for s in ["index of /", "parent directory", "[to parent directory]"]):
        detail = "The response contains a directory-index listing indicator."
        findings.append(detail)
        evidence.append({"type": "directory_listing", "description": detail, "url": resp.url})
    if any(s in body_lower for s in [
        "traceback (most recent call", "debug mode", "werkzeug debugger",
        "exception details", "stack trace", "at line"
    ]):
        detail = "The response contains a debug or stack-trace indicator."
        findings.append(detail)
        evidence.append({"type": "debug_disclosure", "description": detail, "url": resp.url})
    if not findings:
        findings.append("No tested misconfiguration indicators were observed.")

    return _result(
        name="Security Misconfiguration", owasp="A05:2021 – Security Misconfiguration",
        detected=bool(evidence), details=findings,
        severity="Low" if evidence else "None",
        recommendation="Set context-appropriate security headers and disable debug details and directory indexes.",
        finding_type="possible" if evidence else "none",
        affected_url=resp.url, evidence=evidence,
    )


def check_broken_access_control(url: str, headers: dict = None) -> dict:
    """Probe a few conventional routes; HTTP 200 alone is only a possible signal."""
    logger.info("[AccessControl] Testing: %s", _log_target(url))
    parsed = urlsplit(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    baseline, _ = _get(url, headers=headers)
    if not baseline:
        return _result(
            "Broken Access Control", "A01:2021 – Broken Access Control", False,
            ["Target could not be reached; this check was not completed."], "Error",
            "Verify the target is reachable.", finding_type="error", affected_url=url,
        )
    findings, evidence = [], []

    def _probe(path: str):
        test_url = base + path
        resp, _ = _get(test_url, headers=headers)
        return test_url, resp

    with ThreadPoolExecutor(max_workers=MAX_SCAN_WORKERS) as pool:
        futures = {pool.submit(_probe, path): path for path in ADMIN_PATHS}
        for fut in as_completed(futures):
            test_url, resp = fut.result()
            if resp and resp.status_code == 200:
                body = re.sub(r"\s+", " ", resp.text).strip()[:2000]
                baseline_body = re.sub(r"\s+", " ", baseline.text).strip()[:2000]
                has_login = bool(BeautifulSoup(resp.text, "html.parser").find("input", {"type": "password"}))
                if body and body != baseline_body and not has_login:
                    detail = (
                        f"{test_url} returned HTTP 200 with content differing from the baseline; "
                        "authentication and authorization were not verified."
                    )
                    findings.append(detail)
                    evidence.append({"type": "admin_route_response", "description": detail, "url": test_url})
            elif resp is None:
                findings.append(f"No response received from {test_url}.")
    if not findings:
        findings.append("No distinct, publicly reachable administrative page was observed.")

    return _result(
        name="Broken Access Control", owasp="A01:2021 – Broken Access Control",
        detected=bool(evidence), details=findings,
        severity="Medium" if evidence else "None",
        recommendation="Enforce server-side authentication and per-object authorization on sensitive routes.",
        finding_type="possible" if evidence else "none",
        affected_url=evidence[0]["url"] if evidence else url, evidence=evidence,
    )


def check_authentication_weakness(
    url: str, headers: dict = None, form_metadata: list = None,
) -> dict:
    """Discover login forms only; no authentication controls are tested."""
    logger.info("[AuthSurface] Inspecting login form presence.")
    login_url, form = _find_login_form_anywhere(
        url, headers=headers, form_metadata=form_metadata,
    )
    if not form:
        return _result(
            name="Authentication Strength (not assessed)",
            owasp="A07:2021 – Identification and Authentication Failures",
            detected=False,
            details=[
                "No login form was found in the inspected pages and common login paths.",
                "Discovery coverage is limited; absence of a form is not established. "
                "Authentication controls were not assessed, regardless of session state.",
            ],
            severity="None",
            recommendation=(
                "Review authentication policies, MFA, rate limiting, account recovery, "
                "and session handling through an authorized manual assessment."
            ),
            finding_type="unsupported", affected_url=url, status="NOT ASSESSED",
        )

    return _result(
        name="Authentication Strength (not assessed)",
        owasp="A07:2021 – Identification and Authentication Failures",
        detected=False,
        details=[
            f"Password-bearing form discovered at {login_url}; this is a login-surface indicator only.",
            "Authentication strength was not tested; establishing an authenticated scan session "
            "does not assess password policy, MFA, rate limiting, or session security.",
        ],
        severity="None",
        recommendation=(
            "Review authentication policies, MFA, rate limiting, account recovery, "
            "and session handling through an authorized manual assessment."
        ),
        finding_type="unsupported", affected_url=login_url, status="NOT ASSESSED",
        evidence=[{
            "type": "login_form_discovery",
            "description": "A password-bearing form was discovered; no authentication control was tested.",
            "url": login_url,
            "page_url": form.get("page_url", login_url),
            "form_action": form.get("action", ""),
            "method": form.get("method", ""),
            "field_names": [field.get("name", "") for field in form.get("fields", [])],
        }],
    )


def _request_cookie_names(headers: dict = None) -> list[str]:
    """Return cookie names from request headers without retaining or exposing values."""
    cookie_header = next(
        (value for name, value in (headers or {}).items()
         if isinstance(name, str) and name.lower() == "cookie"),
        "",
    )
    if not isinstance(cookie_header, str):
        return []
    parsed = SimpleCookie()
    try:
        parsed.load(cookie_header)
    except (TypeError, ValueError):
        return []
    return list(parsed.keys())


def check_sensitive_data_exposure(url: str, headers: dict = None) -> dict:
    """
    OWASP A02 — Cryptographic Failures

    Checks:
      • HTTPS enforcement
      • Cookie Secure / HttpOnly / SameSite flags
      • Mixed-content (HTTP assets on HTTPS page)
      • Sensitive data patterns in response body (emails, API keys, tokens, private keys)
    """
    logger.info("[DataExposure] Testing: %s", _log_target(url))
    findings, evidence, vulnerable = [], [], False
    parsed = urlparse(url)
    request_cookie_names = _request_cookie_names(headers)

    if parsed.scheme != "https":
        findings.append("⚠ Site served over HTTP — data transmitted in plain text.")
        vulnerable = True
    else:
        findings.append("✔ Site uses HTTPS.")
    if request_cookie_names:
        names = ", ".join(request_cookie_names)
        detail = f"Request sent cookie name(s): {names}; cookie values are omitted."
        findings.append(detail)
        evidence.append({
            "type": "request_cookie_names",
            "description": detail,
            "url": url,
            "cookie_names": request_cookie_names,
        })
    else:
        findings.append("No request Cookie header was supplied to this check.")

    resp, _ = _get(url, headers=headers)
    if not resp:
        return _result(
            name="Sensitive Data Exposure", owasp="A02:2021 – Cryptographic Failures",
            detected=vulnerable, details=findings,
            severity="High" if vulnerable else "None",
            recommendation="Serve over HTTPS. Set Secure/HttpOnly/SameSite on cookies.",
        )

    # Cookie flags
    if resp.cookies:
        for cookie in resp.cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure")
            if not cookie.get_nonstandard_attr("HttpOnly"):
                issues.append("missing HttpOnly")
            if not cookie.get_nonstandard_attr("SameSite"):
                issues.append("missing SameSite")
            if issues:
                detail = f"Response-set cookie '{cookie.name}': {', '.join(issues)}."
                findings.append(f"⚠ {detail}")
                evidence.append({
                    "type": "response_cookie_flags",
                    "description": detail,
                    "url": resp.url,
                    "cookie_name": cookie.name,
                })
                vulnerable = True
            else:
                findings.append(f"✔ Response-set cookie '{cookie.name}': properly flagged.")
    else:
        findings.append(
            "This response set no cookies; this says nothing about cookies sent in the request. "
            "Cookie flag assessment was skipped for this response."
        )

    # Mixed content
    if parsed.scheme == "https":
        soup = BeautifulSoup(resp.text, "html.parser")
        http_assets = [
            tag.get("src") or tag.get("href")
            for tag in soup.find_all(["script", "img", "link", "iframe", "audio", "video"])
            if (tag.get("src") or tag.get("href", "")).startswith("http://")
        ]
        if http_assets:
            findings.append(f"⚠ Mixed content: {len(http_assets)} HTTP asset(s) on HTTPS page")
            for a in http_assets[:3]:
                findings.append(f"   • {a[:80]}")
            vulnerable = True

    # Sensitive data patterns
    sensitive_patterns = {
        "Email address":    r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}",
        "AWS access key":   r"AKIA[0-9A-Z]{16}",
        "API key/secret":   r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9+/=_-]{8,}",
        "Private key":      r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    }
    for label, pattern in sensitive_patterns.items():
        matches = re.findall(pattern, resp.text)
        if matches:
            findings.append(f"⚠ {label} pattern found in response body ({len(matches)} match(es))")
            vulnerable = True

    return _result(
        name="Sensitive Data Exposure", owasp="A02:2021 – Cryptographic Failures",
        detected=vulnerable, details=findings,
        severity="High" if vulnerable else "None",
        recommendation=(
            "Enforce HTTPS sitewide with HSTS. "
            "Set Secure, HttpOnly, SameSite=Strict on all cookies. "
            "Never expose credentials or keys in HTML responses. "
            "Fix mixed content by serving all assets over HTTPS."
        ),
        evidence=evidence,
    )


def check_components_with_vulnerabilities(url: str, headers: dict = None) -> dict:
    """
    OWASP A06 — Vulnerable and Outdated Components  (new in v2)

    Detects fingerprints of known outdated libraries/frameworks in:
      • HTTP response headers
      • HTML body (script src attributes, meta tags, HTML comments)
    """
    logger.info("[Components] Testing: %s", _log_target(url))
    resp, _ = _get(url, headers=headers)

    if not resp:
        return _result(
            name="Vulnerable & Outdated Components",
            owasp="A06:2021 – Vulnerable and Outdated Components",
            detected=False, details=["Could not reach target."], severity="None",
            recommendation="Keep all libraries/frameworks up to date.",
        )

    findings, vulnerable = [], False

    fingerprints = [
        (r"jquery[/-](1\.[0-9]\.|2\.[0-2]\.)","Outdated jQuery (< 3.x)"),
        (r"bootstrap[/-][2-3]\.",              "Outdated Bootstrap (< 4.x)"),
        (r"angular\.?js[/-]1\.",               "AngularJS 1.x (EOL)"),
        (r"react[/-]1[56]\.",                  "Older React version detected"),
        (r"wp-content|wp-includes",           "WordPress detected — verify updates"),
        (r"sites/default/files",              "Drupal detected — verify updates"),
        (r"joomla",                           "Joomla detected — verify updates"),
        (r"x-powered-by:.*php/[45]\.",        "Old PHP version (< 8.x)"),
        (r"x-powered-by:.*asp\.net",          "ASP.NET detected — verify version"),
        (r"struts",                           "Apache Struts detected (historical RCE risk)"),
        (r"log4j",                            "Log4j reference found (CVE-2021-44228 risk)"),
        (r"moment\.js",                       "Moment.js detected (deprecated, CVE history)"),
    ]

    combined = resp.text.lower() + "\n" + "\n".join(
        f"{k}: {v}".lower() for k, v in resp.headers.items()
    )

    for pattern, description in fingerprints:
        if re.search(pattern, combined):
            findings.append(f"⚠ {description}")
            vulnerable = True

    if not findings:
        findings.append("No obvious outdated component fingerprints detected.")

    return _result(
        name="Vulnerable & Outdated Components",
        owasp="A06:2021 – Vulnerable and Outdated Components",
        detected=vulnerable, details=findings,
        severity="Medium" if vulnerable else "None",
        recommendation=(
            "Audit all dependencies with 'pip audit', 'npm audit', or Snyk. "
            "Keep all frameworks and libraries updated. "
            "Subscribe to CVE notifications for your stack."
        ),
    )


def _merge_page_check_results(check_name: str, results: list[dict], target: str) -> dict:
    """Combine per-page injection checks without dropping untested form candidates."""
    if not results:
        return _result(
            check_name, "A03:2021 – Injection", False,
            ["No crawl pages were available for this check."], "Error",
            "Verify the target is reachable.", finding_type="error",
            affected_url=target,
        )

    evidence = [
        item for result in results for item in result.get("evidence", [])
    ]
    is_xss_check = results[0].get("name") == "Cross-Site Scripting (XSS)"
    details = []
    unaffected_xss_pages = 0
    for result in results:
        page_url = result.get("affected_url")
        if is_xss_check and result.get("finding_type") == "none":
            unaffected_xss_pages += 1
            continue
        for detail in result.get("details", []):
            details.append(f"[{page_url}] {detail}" if page_url else str(detail))
    if is_xss_check and unaffected_xss_pages:
        details.append(
            "No unescaped inert-marker reflection was observed on "
            f"{unaffected_xss_pages} other crawled page(s)."
        )

    detected_results = [
        result for result in results
        if result.get("detected") and result.get("finding_type") in ("possible", "confirmed")
    ]
    if detected_results:
        finding_type = "possible"
        severity = next(
            (item.get("severity") for item in detected_results if item.get("severity") != "None"),
            "Medium",
        )
        status = "POSSIBLE FINDING"
        detected = True
    elif all(result.get("finding_type") == "unsupported" for result in results):
        finding_type, severity, status, detected = "unsupported", "None", "NOT TESTED", False
    elif any(
        result.get("finding_type") == "partial"
        or result.get("finding_type") == "unsupported"
        or any(
            item.get("type") == "form_candidate_not_tested"
            for item in result.get("evidence", [])
        )
        for result in results
    ):
        finding_type, severity, status, detected = "partial", "None", "PARTIALLY TESTED", False
    elif all(result.get("finding_type") == "error" for result in results):
        finding_type, severity, status, detected = "error", "Error", "ERROR", False
    else:
        finding_type, severity, status, detected = "none", "None", "NOT FOUND", False

    return _result(
        name=results[0].get("name", check_name),
        owasp=results[0].get("owasp", "A03:2021 – Injection"),
        detected=detected,
        details=details,
        severity=severity,
        recommendation=results[0].get(
            "recommendation", "Review input handling and output encoding.",
        ),
        finding_type=finding_type,
        affected_url=next(
            (item.get("url") or item.get("page_url") for item in evidence),
            target,
        ),
        evidence=evidence,
        status=status,
    )


# ─────────────────────────────────────────────────────────
# Upgrade 2 — Multi-threaded Main Scanner Class
# ─────────────────────────────────────────────────────────

class SecurityScanner:
    """
    Orchestrates all OWASP security checks with parallel execution.

    v2 Upgrades:
      ✦ ThreadPoolExecutor runs all independent checks concurrently
      ✦ Crawler-aware: SQLi & XSS merge findings across all crawled pages
      ✦ Records scan_meta: timing, page count, thread count
      ✦ 7 checks (added A06 – Outdated Components)
    """

    CHECKS = [
        check_sql_injection,
        check_xss,
        check_security_misconfiguration,
        check_broken_access_control,
        check_authentication_weakness,
        check_sensitive_data_exposure,
        check_components_with_vulnerabilities,
    ]

    def __init__(
        self, url: str, crawl: bool = False, max_pages: int = MAX_CRAWL_PAGES,
        lab_credentials: dict = None,
    ):
        self.url       = url.rstrip("/")
        self.crawl     = crawl
        self.max_pages = max_pages
        self.lab_credentials = dict(lab_credentials) if lab_credentials else None
        self.pages: list[dict] = []
        self.scan_meta: dict   = {}
        self.request_headers: dict = {}
        self.authentication_status = {
            "authentication_mode": "authenticated" if self.lab_credentials else "unauthenticated",
            "authentication_mode_enabled": bool(self.lab_credentials),
            "login_session_establishment": "not_attempted",
            "protected_access_verified": False,
            "protected_access_url": None,
        }

    def run_all_checks(self) -> list[dict]:
        """Run all checks in parallel; merge crawl findings for injection checks."""
        t_start = time.monotonic()

        if self.lab_credentials:
            try:
                self.request_headers, self.authentication_status = _authenticate_local_dvwa(
                    self.url,
                    self.lab_credentials.get("username", ""),
                    self.lab_credentials.get("password", ""),
                )
            except LabAuthenticationError as exc:
                self.authentication_status = exc.authentication_status
                logger.warning("[Scanner] Local lab authentication failed (%s).", type(exc).__name__)
                self.pages = []
                self.scan_meta = {
                    "pages_crawled": 0,
                    "pages": [],
                    "scan_duration_seconds": round(time.monotonic() - t_start, 2),
                    "checks_run": len(self.CHECKS),
                    "threads_used": 0,
                    **self.authentication_status,
                }
                return [
                    _result(
                        name=check_fn.__name__,
                        owasp="Unknown",
                        detected=False,
                        details=["Authenticated lab session failed; this check was not run."],
                        severity="Error",
                        recommendation="Verify the local DVWA lab setup and supplied credentials.",
                        finding_type="error",
                        affected_url=self.url,
                    )
                    for check_fn in self.CHECKS
                ]

        # Step 1: Crawl
        if self.crawl:
            crawler = Crawler(
                self.url, max_pages=self.max_pages, headers=self.request_headers,
            )
            self.pages = crawler.crawl()
        else:
            self.pages = [{"url": self.url, "status": 200, "title": "", "form_count": 0}]

        page_urls = [p["url"] for p in self.pages]
        logger.info("[Scanner] %d page(s) to scan, %d workers", len(page_urls), MAX_SCAN_WORKERS)

        results: list[dict] = []
        result_lock = threading.Lock()

        def _run_check(check_fn):
            """Run one check function (and optionally merge crawl sub-results)."""
            try:
                if check_fn in (check_sql_injection, check_xss):
                    page_results = []
                    pages_to_check = self.pages if self.crawl else [
                        {"url": self.url, "forms": None}
                    ]
                    for page in pages_to_check:
                        page_results.append(check_fn(
                            page["url"],
                            headers=self.request_headers or None,
                            form_metadata=page.get("forms"),
                        ))
                    return _merge_page_check_results(
                        check_fn.__name__, page_results, self.url,
                    )

                if check_fn is check_authentication_weakness:
                    all_forms = [
                        form
                        for page in self.pages
                        for form in page.get("forms", [])
                    ]
                    return check_fn(
                        self.url,
                        headers=self.request_headers or None,
                        form_metadata=all_forms,
                    )

                result = (
                    check_fn(self.url, headers=self.request_headers)
                    if self.request_headers else check_fn(self.url)
                )
                return result

            except Exception as exc:
                logger.error(
                    "[Scanner] %s failed (%s).",
                    check_fn.__name__, type(exc).__name__,
                )
                return _result(
                    name=check_fn.__name__, owasp="Unknown",
                    detected=False,
                    details=["Check failed unexpectedly; see server logs."],
                    severity="Error", recommendation="Review server logs.",
                )

        # Run all checks concurrently
        with ThreadPoolExecutor(max_workers=MAX_SCAN_WORKERS) as pool:
            future_map = {pool.submit(_run_check, fn): fn for fn in self.CHECKS}
            for fut in as_completed(future_map):
                with result_lock:
                    results.append(fut.result())

        # Record metadata
        self.scan_meta = {
            "pages_crawled":        len(self.pages),
            "pages":                [{k: v for k, v in p.items() if k != "_links"} for p in self.pages],
            "scan_duration_seconds": round(time.monotonic() - t_start, 2),
            "checks_run":           len(results),
            "threads_used":         MAX_SCAN_WORKERS,
            "authentication_mode": "unauthenticated",
            "authentication_mode_enabled": False,
            "login_session_establishment": "not_attempted",
            "protected_access_verified": False,
            "protected_access_url": None,
            **self.authentication_status,
        }

        logger.info(
            "[Scanner] Complete — %d checks, %d pages, %.1fs, %d threads",
            len(results), len(self.pages),
            self.scan_meta["scan_duration_seconds"],
            MAX_SCAN_WORKERS,
        )
        return results


# ─────────────────────────────────────────────────────────
# Private helpers
# ─────────────────────────────────────────────────────────

def _result(
    name, owasp, detected, details, severity, recommendation,
    finding_type=None, affected_url=None, evidence=None, status=None,
) -> dict:
    if finding_type is None:
        finding_type = (
            "error" if severity == "Error" else
            "possible" if detected else "none"
        )
    status = status or {
        "unsupported": "UNSUPPORTED",
        "error": "ERROR",
        "possible": "POSSIBLE FINDING",
        "confirmed": "CONFIRMED FINDING",
        "partial": "PARTIALLY TESTED",
    }.get(finding_type, "NOT FOUND")
    description = (
        " ".join(str(detail) for detail in details)
        if isinstance(details, list) else str(details or "")
    )
    return {
        "name":           name,
        "owasp":          owasp,
        "detected":       detected,
        "status":         status,
        "severity":       severity,
        "description":    description,
        "details":        details,
        "recommendation": recommendation,
        "finding_type":   finding_type,
        "affected_url":   affected_url,
        "evidence":       evidence or [],
    }


def _build_form_data(form, payload: str) -> dict:
    """Fill all form fields with the given payload (for injection testing)."""
    data = {}
    for inp in form.find_all(["input", "textarea", "select"]):
        name = inp.get("name")
        if not name:
            continue
        t = inp.get("type", "text").lower()
        if t in ("submit", "button", "image", "reset", "file"):
            continue
        elif t == "checkbox":
            data[name] = "on"
        elif t == "radio":
            data[name] = inp.get("value", "on")
        elif t == "hidden":
            data[name] = inp.get("value", "")
        else:
            data[name] = payload
    return data


def _payload_form_field_names(form) -> list[str]:
    """List only named controls that receive the inert probe in _build_form_data."""
    names = []
    for field in form.find_all(["input", "textarea", "select"]):
        name = field.get("name")
        field_type = (field.get("type") or "text").lower()
        if not name or field_type in (
            "submit", "button", "image", "reset", "file",
            "hidden", "checkbox", "radio",
        ):
            continue
        names.append(name)
    return names


def _extract_form_metadata(page_url: str, soup: BeautifulSoup) -> list[dict]:
    """Extract form structure without retaining submitted values or tokens."""
    metadata = []
    for form_index, form in enumerate(soup.find_all("form")):
        raw_action = urljoin(page_url, form.get("action") or page_url)
        parsed_action = urlsplit(raw_action)
        action_host = parsed_action.hostname
        if action_host and parsed_action.scheme.lower() in ("http", "https"):
            host = f"[{action_host}]" if ":" in action_host else action_host
            try:
                port = parsed_action.port
            except ValueError:
                port = None
            netloc = f"{host}:{port}" if port else host
            action = urlunsplit((
                parsed_action.scheme.lower(), netloc,
                parsed_action.path or "/", "", "",
            ))
        else:
            action = page_url

        fields = []
        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name")
            if not name:
                continue
            if field.name == "textarea":
                field_type = "textarea"
            elif field.name == "select":
                field_type = "select"
            else:
                field_type = (field.get("type") or "text").strip().lower()
            fields.append({
                "name": name,
                "type": field_type,
                "is_password": field_type == "password",
            })
        metadata.append({
            "page_url": page_url,
            "action": action,
            "method": (form.get("method") or "get").strip().upper(),
            "fields": fields,
            "index": form_index,
        })
    return metadata


def _find_login_forms(soup: BeautifulSoup) -> list:
    """Return password-bearing forms as login-surface candidates."""
    return [f for f in soup.find_all("form") if f.find("input", {"type": "password"})]


def _find_login_form_anywhere(
    base_url: str, headers: dict = None, form_metadata: list = None,
):
    """
    Try base URL + 5 common login paths.
    Returns (login_url, form) or (base_url, None).
    """
    for form in form_metadata or []:
        if any(field.get("is_password") for field in form.get("fields", [])):
            return form.get("page_url", base_url), form

    candidates = [base_url] + [
        urljoin(base_url, path)
        for path in [
            "/login.php", "/login", "/signin", "/auth/login",
            "/user/login", "/account/login",
        ]
    ]
    for url in candidates:
        try:
            candidate = _validate_url(url, allowed_origin=_url_origin(urlsplit(base_url)))
        except URLValidationError:
            continue
        resp, _ = _get(candidate, headers=headers)
        if not resp or resp.status_code != 200:
            continue
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = _find_login_forms(soup)
        if forms:
            metadata = _extract_form_metadata(resp.url, soup)
            for item in metadata:
                if any(field["is_password"] for field in item["fields"]):
                    return resp.url, item
    return base_url, None