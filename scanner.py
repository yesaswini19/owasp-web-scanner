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
  ✦ Multi-signal auth success detection (redirect + keywords + length + lockout)

DISCLAIMER: Educational and authorized testing only.
All payloads are benign probes — no real exploitation performed.
"""

import logging
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, urlunparse, urlencode, parse_qs

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────
# Tuneable constants
# ─────────────────────────────────────────────────────────
REQUEST_TIMEOUT   = 10          # seconds per HTTP request
MAX_CRAWL_PAGES   = 20          # max unique pages the crawler visits
MAX_SCAN_WORKERS  = 6           # parallel workers for concurrent checks
MAX_CRAWL_WORKERS = 8           # parallel workers for crawling
RESPONSE_LEN_DELTA_THRESHOLD = 0.20   # >20% body-size change flags anomaly
TIME_SPIKE_THRESHOLD = 3.0            # >3 s response time = possible time-based SQLi

USER_AGENT = "Mozilla/5.0 (compatible; OWASPScanner/2.0; +https://owasp.org)"

# ── SQL Injection payloads ────────────────────────────────
# Covers: error-based, boolean-based, time-based, string termination
SQL_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1\" --",
    "1 AND 1=1",           # boolean true  (compare length to false)
    "1 AND 1=2",           # boolean false (different response = vulnerable)
    "1; SELECT SLEEP(3)--",           # MySQL time-based
    "1 WAITFOR DELAY '0:0:3'--",      # MSSQL time-based
    "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--",
]

# ── XSS payloads ──────────────────────────────────────────
XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    '"><svg onload=alert(1)>',
    "<body onload=alert('xss')>",
    "';alert('xss')//",
    '"><iframe src=javascript:alert(1)>',
]

# ── Admin / sensitive paths for access control checks ─────
ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/wp-admin", "/wp-login.php",
    "/dashboard", "/management", "/control", "/cpanel", "/phpmyadmin",
    "/login", "/admin/login", "/user/login", "/auth/login",
    "/api/admin", "/api/v1/admin", "/.env", "/config", "/backup",
    "/server-status", "/actuator", "/actuator/health",
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

# ── Weak credential list for auth simulation ──────────────
WEAK_CREDENTIALS = [
    ("admin",  "admin"),
    ("admin",  "password"),
    ("admin",  "123456"),
    ("admin",  "admin123"),
    ("root",   "root"),
    ("root",   "toor"),
    ("test",   "test"),
    ("user",   "user"),
    ("guest",  "guest"),
]

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

# Keywords suggesting successful login on the returned page
LOGIN_SUCCESS_PATTERNS = [
    "logout", "sign out", "signout", "log out",
    "dashboard", "welcome", "profile", "my account",
    "account settings", "control panel",
]

# Per-thread session for connection reuse (thread-safe pooling)
_thread_local = threading.local()


def _session() -> requests.Session:
    """Return a per-thread requests.Session (connection pooling, keep-alive)."""
    if not hasattr(_thread_local, "session"):
        s = requests.Session()
        s.headers.update({"User-Agent": USER_AGENT})
        s.verify = False       # Skip SSL cert verification for test environments
        _thread_local.session = s
    return _thread_local.session


# ─────────────────────────────────────────────────────────
# Low-level HTTP helpers
# ─────────────────────────────────────────────────────────

def _get(url: str, params: dict = None, **kwargs):
    """Thread-safe GET. Returns (response | None, elapsed_seconds)."""
    try:
        t0 = time.monotonic()
        resp = _session().get(
            url, params=params,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            **kwargs,
        )
        return resp, time.monotonic() - t0
    except requests.exceptions.ConnectionError as e:
        logger.debug("Connection error %s: %s", url, e)
    except requests.exceptions.Timeout:
        logger.debug("Timeout %s", url)
    except requests.exceptions.RequestException as e:
        logger.debug("GET failed %s: %s", url, e)
    return None, 0.0


def _post(url: str, data: dict = None, **kwargs):
    """Thread-safe POST. Returns (response | None, elapsed_seconds)."""
    try:
        t0 = time.monotonic()
        resp = _session().post(
            url, data=data,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            **kwargs,
        )
        return resp, time.monotonic() - t0
    except requests.exceptions.RequestException as e:
        logger.debug("POST failed %s: %s", url, e)
    return None, 0.0


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

    def __init__(self, seed_url: str, max_pages: int = MAX_CRAWL_PAGES):
        self.seed_url    = seed_url
        self.max_pages   = max_pages
        self.base_domain = urlparse(seed_url).netloc
        self._visited    = set()
        self._lock       = threading.Lock()
        self.pages: list[dict] = []

    def crawl(self) -> list[dict]:
        """Crawl from seed and return list of page metadata dicts."""
        logger.info("[Crawler] Starting from %s (max=%d)", self.seed_url, self.max_pages)
        queue = [self.seed_url]

        with ThreadPoolExecutor(max_workers=MAX_CRAWL_WORKERS) as pool:
            while queue and len(self.pages) < self.max_pages:
                batch = []
                while queue and len(batch) < MAX_CRAWL_WORKERS:
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
                    result = fut.result()
                    if result:
                        with self._lock:
                            if len(self.pages) < self.max_pages:
                                self.pages.append(result)
                        queue.extend(result.pop("_links", []))

        logger.info("[Crawler] Complete — %d pages discovered", len(self.pages))
        return self.pages

    def page_urls(self) -> list[str]:
        return [p["url"] for p in self.pages]

    def _fetch_page(self, url: str) -> dict | None:
        resp, elapsed = _get(url)
        if not resp:
            return None
        ct = resp.headers.get("Content-Type", "")
        if "text/html" not in ct:
            return None

        soup = BeautifulSoup(resp.text, "html.parser")
        title = (soup.title.string or "").strip() if soup.title else "(no title)"
        forms = soup.find_all("form")

        links = []
        for tag in soup.find_all("a", href=True):
            abs_link = urljoin(url, tag["href"])
            norm = self._normalize(abs_link)
            p = urlparse(abs_link)
            if (
                p.scheme in ("http", "https")
                and p.netloc == self.base_domain
                and not self._skip_ext(p.path)
            ):
                with self._lock:
                    if norm not in self._visited:
                        links.append(abs_link)

        logger.debug("[Crawler] %s HTTP %d | %d forms | %d links | %.2fs",
                     url, resp.status_code, len(forms), len(links), elapsed)

        return {
            "url":        url,
            "status":     resp.status_code,
            "title":      title,
            "form_count": len(forms),
            "elapsed":    round(elapsed, 3),
            "_links":     links,
        }

    @staticmethod
    def _normalize(url: str) -> str:
        p = urlparse(url)
        return urlunparse((p.scheme.lower(), p.netloc.lower(), p.path, "", "", ""))

    @staticmethod
    def _skip_ext(path: str) -> bool:
        ext = ("." + path.rsplit(".", 1)[-1].lower()) if "." in path else ""
        return ext in Crawler.SKIP_EXTENSIONS


# ─────────────────────────────────────────────────────────
# Upgrade 3 — Advanced Detection Logic Helpers
# ─────────────────────────────────────────────────────────

def _contains_sql_error(text: str) -> bool:
    """Pattern-match 15 known DB error strings across 4 engine families."""
    t = text.lower()
    return any(re.search(p, t) for p in SQL_ERROR_PATTERNS)


def _response_length_anomaly(baseline_len: int, probe_len: int) -> bool:
    """True if body size changed by > RESPONSE_LEN_DELTA_THRESHOLD (20%)."""
    if baseline_len == 0:
        return False
    return abs(probe_len - baseline_len) / baseline_len > RESPONSE_LEN_DELTA_THRESHOLD


def _status_code_anomaly(baseline: int, probe: int) -> bool:
    """True if probe returned a 500 (server error) or unexpected redirect."""
    return probe == 500 or (baseline == 200 and probe in (301, 302))


def _time_spike(elapsed: float) -> bool:
    """True if response time suggests a time-based injection succeeded."""
    return elapsed >= TIME_SPIKE_THRESHOLD


def _analyze_sqli_response(baseline_resp, probe_resp, elapsed: float, payload: str) -> str | None:
    """
    Multi-signal SQLi analysis combining:
      1. DB error string matching
      2. Response body length delta
      3. HTTP status code deviation
      4. Response time spike
    Returns a human-readable finding string or None.
    """
    if probe_resp is None:
        return None

    signals = []

    if _contains_sql_error(probe_resp.text):
        signals.append("DB error string in response")

    if baseline_resp and _response_length_anomaly(len(baseline_resp.text), len(probe_resp.text)):
        signals.append(
            f"body size changed ({len(baseline_resp.text)}→{len(probe_resp.text)} bytes)"
        )

    if baseline_resp and _status_code_anomaly(baseline_resp.status_code, probe_resp.status_code):
        signals.append(
            f"status changed ({baseline_resp.status_code}→{probe_resp.status_code})"
        )

    if _time_spike(elapsed):
        signals.append(f"response-time spike {elapsed:.1f}s (possible time-based SQLi)")

    return f"Payload {payload!r} → " + "; ".join(signals) if signals else None


# ─────────────────────────────────────────────────────────
# Individual Security Check Functions
# ─────────────────────────────────────────────────────────

def check_sql_injection(url: str) -> dict:
    """
    OWASP A03 — Injection (SQL Injection)

    Detection signals:
      • DB error pattern matching (15 patterns, 4 DB engines)
      • Response body-length delta vs. baseline
      • HTTP status-code deviation (500 / unexpected redirect)
      • Response time spike (time-based SQLi hint)
    Targets: URL query parameters AND HTML form inputs.
    """
    logger.info("[SQLi] Testing: %s", url)
    findings, vulnerable = [], False

    baseline_resp, _ = _get(url)

    # ── 1. Query-parameter injection ──────────────────
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if params:
        for param_name in list(params.keys()):
            for payload in SQL_PAYLOADS:
                test_params = dict(params)
                test_params[param_name] = [payload]
                test_url = (
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    f"?{urlencode(test_params, doseq=True)}"
                )
                probe_resp, elapsed = _get(test_url)
                finding = _analyze_sqli_response(baseline_resp, probe_resp, elapsed, payload)
                if finding:
                    vulnerable = True
                    findings.append(f"Param '{param_name}': {finding}")
                    logger.warning("[SQLi] %s param='%s' payload=%r", url, param_name, payload)
                    break
    else:
        findings.append("No query parameters — skipping parameter injection.")

    # ── 2. Form-field injection ───────────────────────
    if baseline_resp:
        soup = BeautifulSoup(baseline_resp.text, "html.parser")
        for form in soup.find_all("form"):
            action = urljoin(url, form.get("action") or url)
            method = form.get("method", "get").lower()
            for payload in SQL_PAYLOADS[:4]:
                form_data = _build_form_data(form, payload)
                if not form_data:
                    continue
                probe_resp, elapsed = (
                    _post(action, data=form_data) if method == "post"
                    else _get(action, params=form_data)
                )
                finding = _analyze_sqli_response(baseline_resp, probe_resp, elapsed, payload)
                if finding:
                    vulnerable = True
                    findings.append(f"Form @ {action}: {finding}")
                    break

    return _result(
        name="SQL Injection",
        owasp="A03:2021 – Injection",
        detected=vulnerable,
        details=findings or ["No SQLi signals detected."],
        severity="Critical" if vulnerable else "None",
        recommendation=(
            "Use parameterised queries / prepared statements. "
            "Apply an ORM layer and validate all inputs server-side. "
            "Enable WAF rules for SQL injection patterns."
        ),
    )


def check_xss(url: str) -> dict:
    """
    OWASP A03 — Injection (Cross-Site Scripting)

    Detection signals:
      • Full payload reflection in response body
      • Partial reflection (tags stripped, JS/event-handler remains)
      • Response length anomaly on injected forms
    """
    logger.info("[XSS] Testing: %s", url)
    findings, vulnerable = [], False

    baseline_resp, _ = _get(url)
    if not baseline_resp:
        return _result(
            name="Cross-Site Scripting (XSS)", owasp="A03:2021 – Injection",
            detected=False, details=["Could not reach target."], severity="None",
            recommendation="Encode all user output. Implement a Content-Security-Policy.",
        )

    def _test_xss(probe_resp, payload: str, context: str) -> str | None:
        if probe_resp is None:
            return None
        if payload in probe_resp.text:
            return f"Full payload reflected in {context}"
        stripped = re.sub(r"<[^>]+>", "", payload)
        if stripped and stripped in probe_resp.text:
            return f"Partial reflection (tags stripped) in {context}"
        if _response_length_anomaly(len(baseline_resp.text), len(probe_resp.text)):
            return f"Response length anomaly in {context}"
        return None

    soup = BeautifulSoup(baseline_resp.text, "html.parser")
    forms = soup.find_all("form")

    if forms:
        for form in forms:
            action = urljoin(url, form.get("action") or url)
            method = form.get("method", "get").lower()
            for payload in XSS_PAYLOADS:
                form_data = _build_form_data(form, payload)
                probe, _ = (
                    _post(action, data=form_data) if method == "post"
                    else _get(action, params=form_data)
                )
                finding = _test_xss(probe, payload, f"form@{action}")
                if finding:
                    vulnerable = True
                    findings.append(f"Payload {payload!r} → {finding}")
                    logger.warning("[XSS] %s form=%s", url, action)
                    break
    else:
        for payload in XSS_PAYLOADS:
            probe, _ = _get(url, params={"q": payload, "search": payload})
            finding = _test_xss(probe, payload, "URL parameter")
            if finding:
                vulnerable = True
                findings.append(f"Payload {payload!r} → {finding}")
                break
        if not findings:
            findings.append("No forms or reflectable parameters found.")

    return _result(
        name="Cross-Site Scripting (XSS)", owasp="A03:2021 – Injection",
        detected=vulnerable,
        details=findings or ["No XSS reflection detected."],
        severity="High" if vulnerable else "None",
        recommendation=(
            "HTML-encode all user-supplied output before rendering. "
            "Implement a strict Content-Security-Policy header. "
            "Use auto-escaping template engines (Jinja2, React JSX, etc.)."
        ),
    )


def check_security_misconfiguration(url: str) -> dict:
    """
    OWASP A05 — Security Misconfiguration

    Checks:
      • 8 required HTTP security headers
      • Server / X-Powered-By version disclosure
      • Directory listing indicators
      • Debug / stack trace leakage in response body
    """
    logger.info("[MiscConfig] Testing: %s", url)
    resp, _ = _get(url)

    if not resp:
        return _result(
            name="Security Misconfiguration", owasp="A05:2021 – Security Misconfiguration",
            detected=True, details=["Target unreachable — cannot verify headers."],
            severity="Unknown", recommendation="Ensure the server is accessible.",
        )

    findings, vulnerable = [], False
    resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    # ── Security headers ──────────────────────────────
    for header, description in REQUIRED_HEADERS.items():
        if header.lower() in resp_headers_lower:
            findings.append(f"✔ {header}: present")
        else:
            findings.append(f"✘ MISSING: {header} — {description}")
            vulnerable = True

    # ── Version disclosure ────────────────────────────
    for h in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"):
        val = resp.headers.get(h, "")
        if val and any(c.isdigit() for c in val):
            findings.insert(0, f"⚠ Version disclosed via '{h}': {val!r}")
            vulnerable = True

    # ── Directory listing ─────────────────────────────
    body_lower = resp.text.lower()
    if any(s in body_lower for s in ["index of /", "parent directory", "[to parent directory]"]):
        findings.insert(0, "⚠ Directory listing appears ENABLED")
        vulnerable = True

    # ── Debug / error info leakage ────────────────────
    if any(s in body_lower for s in [
        "traceback (most recent call", "debug mode", "werkzeug debugger",
        "exception details", "stack trace", "at line"
    ]):
        findings.insert(0, "⚠ Debug information / stack trace exposed in response")
        vulnerable = True

    return _result(
        name="Security Misconfiguration", owasp="A05:2021 – Security Misconfiguration",
        detected=vulnerable, details=findings,
        severity="Medium" if vulnerable else "None",
        recommendation=(
            "Add all missing security headers in your web server config. "
            "Remove Server/X-Powered-By version strings. "
            "Disable directory listing. Turn off debug mode in production."
        ),
    )


def check_broken_access_control(url: str) -> dict:
    """
    OWASP A01 — Broken Access Control

    Checks:
      • 20 common admin/sensitive paths (parallelised)
      • HTTP 200 on admin path without auth = exposed
      • IDOR hint: tries adjacent numeric IDs if URL contains one
    """
    logger.info("[AccessControl] Testing: %s", url)
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    findings, vulnerable = [], False

    def _probe(path: str) -> str:
        test_url = base + path
        resp, _ = _get(test_url)
        if resp is None:
            return f"  (no response): {test_url}"
        if resp.status_code == 200:
            return f"⚠ EXPOSED (HTTP 200): {test_url}"
        elif resp.status_code in (301, 302):
            loc = resp.headers.get("Location", "?")
            return f"→ Redirect {resp.status_code}: {test_url} → {loc}"
        return f"✔ Protected (HTTP {resp.status_code}): {test_url}"

    # Parallelise all path probes
    with ThreadPoolExecutor(max_workers=MAX_SCAN_WORKERS) as pool:
        futures = {pool.submit(_probe, path): path for path in ADMIN_PATHS}
        for fut in as_completed(futures):
            msg = fut.result()
            findings.append(msg)
            if "EXPOSED" in msg:
                vulnerable = True
                logger.warning("[AccessControl] %s", msg)

    # ── IDOR hint ─────────────────────────────────────
    numeric = re.search(r"/(\d+)(?:/|$|\?)", url)
    if numeric:
        orig_id = int(numeric.group(1))
        for tid in [orig_id - 1, orig_id + 1]:
            if tid < 0:
                continue
            test_url = url.replace(f"/{orig_id}", f"/{tid}", 1)
            resp, _ = _get(test_url)
            if resp and resp.status_code == 200:
                findings.insert(0,
                    f"⚠ IDOR hint: ID {tid} returned HTTP 200 — {test_url}"
                )
                vulnerable = True

    return _result(
        name="Broken Access Control", owasp="A01:2021 – Broken Access Control",
        detected=vulnerable,
        details=findings or ["No unprotected admin paths found."],
        severity="High" if vulnerable else "None",
        recommendation=(
            "Enforce authentication and RBAC on ALL sensitive routes. "
            "Return 403 for unauthorised access (not 404). "
            "Validate object-level access for every resource (prevent IDOR)."
        ),
    )


def check_authentication_weakness(url: str) -> dict:
    """
    OWASP A07 — Identification and Authentication Failures

    Checks:
      • Finds login form (main page + 5 common login paths)
      • Simulates 9 weak credential pairs
      • Multi-signal success detection:
          - HTTP redirect after POST
          - Success keywords in response body
          - Response length increase (dashboard loaded)
          - Absence of failure keywords
      • Rate-limit / lockout detection
    """
    logger.info("[AuthWeakness] Testing: %s", url)
    findings, vulnerable = [], False

    login_url, form = _find_login_form_anywhere(url)
    if not form:
        findings.append("No login form detected — authentication check skipped.")
        return _result(
            name="Authentication Weakness",
            owasp="A07:2021 – Identification and Authentication Failures",
            detected=False, details=findings, severity="None",
            recommendation=(
                "Implement MFA, strong password policies, "
                "and account lockout after repeated failures."
            ),
        )

    findings.append(f"Login form found at: {login_url}")
    action = urljoin(login_url, form.get("action") or login_url)
    method = form.get("method", "post").lower()

    # Baseline: wrong credentials to calibrate "failure" response length
    dummy = _build_login_form_data(form, "__BADUSER__", "__BADPASS__")
    baseline_resp, _ = (
        _post(action, data=dummy) if method == "post" else _get(action, params=dummy)
    )
    baseline_len = len(baseline_resp.text) if baseline_resp else 0

    lockout = False
    for username, password in WEAK_CREDENTIALS:
        if lockout:
            findings.append("⚠ Rate-limiting / lockout detected — stopping credential test.")
            break

        form_data = _build_login_form_data(form, username, password)
        resp, _ = (
            _post(action, data=form_data) if method == "post"
            else _get(action, params=form_data)
        )
        if not resp:
            continue

        body_lower = resp.text.lower()
        success_signals = []

        if resp.status_code in (301, 302):
            success_signals.append(f"redirect to {resp.headers.get('Location','?')!r}")

        if any(kw in body_lower for kw in LOGIN_SUCCESS_PATTERNS):
            success_signals.append("success keywords in body")

        if baseline_len and _response_length_anomaly(baseline_len, len(resp.text)):
            success_signals.append(
                f"body size spike ({baseline_len}→{len(resp.text)} bytes)"
            )

        failure_keywords = ["invalid", "incorrect", "wrong", "failed", "error", "denied"]
        has_failure = any(kw in body_lower for kw in failure_keywords)

        if "too many" in body_lower or "locked" in body_lower or resp.status_code == 429:
            lockout = True

        if success_signals and not has_failure:
            vulnerable = True
            findings.append(
                f"⚠ WEAK CREDENTIAL ACCEPTED — {username!r}/{password!r} "
                f"[{'; '.join(success_signals)}]"
            )
            logger.warning("[AuthWeakness] Credential accepted: %s/%s", username, password)
        else:
            findings.append(f"  ✔ Rejected: {username!r}/{password!r}")

        time.sleep(0.25)   # Polite delay

    return _result(
        name="Authentication Weakness",
        owasp="A07:2021 – Identification and Authentication Failures",
        detected=vulnerable, details=findings,
        severity="Critical" if vulnerable else "None",
        recommendation=(
            "Enforce strong passwords (12+ chars, mixed case, symbols). "
            "Implement account lockout after 5 failed attempts. "
            "Require MFA. Use bcrypt/Argon2 for hashing."
        ),
    )


def check_sensitive_data_exposure(url: str) -> dict:
    """
    OWASP A02 — Cryptographic Failures

    Checks:
      • HTTPS enforcement
      • Cookie Secure / HttpOnly / SameSite flags
      • Mixed-content (HTTP assets on HTTPS page)
      • Sensitive data patterns in response body (emails, API keys, tokens, private keys)
    """
    logger.info("[DataExposure] Testing: %s", url)
    findings, vulnerable = [], False
    parsed = urlparse(url)

    if parsed.scheme != "https":
        findings.append("⚠ Site served over HTTP — data transmitted in plain text.")
        vulnerable = True
    else:
        findings.append("✔ Site uses HTTPS.")

    resp, _ = _get(url)
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
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("missing HttpOnly")
            if not cookie.has_nonstandard_attr("SameSite"):
                issues.append("missing SameSite")
            if issues:
                findings.append(f"⚠ Cookie '{cookie.name}': {', '.join(issues)}")
                vulnerable = True
            else:
                findings.append(f"✔ Cookie '{cookie.name}': properly flagged.")
    else:
        findings.append("No cookies set — cookie flag check skipped.")

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
    )


def check_components_with_vulnerabilities(url: str) -> dict:
    """
    OWASP A06 — Vulnerable and Outdated Components  (new in v2)

    Detects fingerprints of known outdated libraries/frameworks in:
      • HTTP response headers
      • HTML body (script src attributes, meta tags, HTML comments)
    """
    logger.info("[Components] Testing: %s", url)
    resp, _ = _get(url)

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

    def __init__(self, url: str, crawl: bool = False, max_pages: int = MAX_CRAWL_PAGES):
        self.url       = url.rstrip("/")
        self.crawl     = crawl
        self.max_pages = max_pages
        self.pages: list[dict] = []
        self.scan_meta: dict   = {}

    def run_all_checks(self) -> list[dict]:
        """Run all checks in parallel; merge crawl findings for injection checks."""
        t_start = time.monotonic()

        # Step 1: Crawl
        if self.crawl:
            crawler = Crawler(self.url, max_pages=self.max_pages)
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
                result = check_fn(self.url)

                # For injection checks, also run across extra crawled pages
                if self.crawl and check_fn in (check_sql_injection, check_xss):
                    with ThreadPoolExecutor(max_workers=MAX_CRAWL_WORKERS) as sub_pool:
                        sub_futures = {
                            sub_pool.submit(check_fn, purl): purl
                            for purl in page_urls[1:]
                        }
                        for fut in as_completed(sub_futures):
                            extra = fut.result()
                            if extra["detected"]:
                                result["detected"] = True
                                result["severity"] = extra["severity"]
                                result["details"].extend([
                                    f"[{sub_futures[fut]}] {d}"
                                    for d in extra["details"]
                                ])
                return result

            except Exception as exc:
                logger.error("[Scanner] %s failed: %s", check_fn.__name__, exc, exc_info=True)
                return _result(
                    name=check_fn.__name__, owasp="Unknown",
                    detected=False, details=[f"Check error: {exc}"],
                    severity="Error", recommendation="See server logs.",
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

def _result(name, owasp, detected, details, severity, recommendation) -> dict:
    return {
        "name":           name,
        "owasp":          owasp,
        "detected":       detected,
        "status":         "DETECTED" if detected else "NOT FOUND",
        "severity":       severity,
        "details":        details,
        "recommendation": recommendation,
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


def _build_login_form_data(form, username: str, password: str) -> dict:
    """Fill login form fields with username/password using name heuristics."""
    data = {}
    for inp in form.find_all(["input", "textarea"]):
        name = inp.get("name", "")
        if not name:
            continue
        t = inp.get("type", "text").lower()
        if t in ("submit", "button", "reset", "file"):
            continue
        name_lower = name.lower()
        if t == "password" or "pass" in name_lower:
            data[name] = password
        elif t == "hidden":
            data[name] = inp.get("value", "")
        elif t in ("text", "email") or any(
            k in name_lower for k in ("user", "login", "email", "name", "id")
        ):
            data[name] = username
        else:
            data[name] = inp.get("value", "test")
    return data


def _find_login_forms(soup: BeautifulSoup) -> list:
    """Return all forms that contain a password input."""
    return [f for f in soup.find_all("form") if f.find("input", {"type": "password"})]


def _find_login_form_anywhere(base_url: str):
    """
    Try base URL + 5 common login paths.
    Returns (login_url, form) or (base_url, None).
    """
    candidates = [base_url] + [
        urljoin(base_url, path)
        for path in ["/login", "/signin", "/auth/login", "/user/login", "/account/login"]
    ]
    for url in candidates:
        resp, _ = _get(url)
        if not resp or resp.status_code != 200:
            continue
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = _find_login_forms(soup)
        if forms:
            return url, forms[0]
    return base_url, None