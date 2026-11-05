# OWASP Top 10 Security Scanner

A local Flask dashboard for limited, heuristic HTTP security checks. This is an educational aid for systems you own or are explicitly authorized to assess; it is not a certification tool, a penetration-testing framework, or a substitute for manual review.

## Features

- Flask dashboard and JSON API.
- Seven check types, including an explicit unsupported/not-tested A07 result, for selected signals in five OWASP Top 10:2021 categories.
- Optional same-host crawl, capped at 20 unique pages.
- Per-thread HTTP request contexts, socket inactivity timeouts, response-size limits, redirect validation, and DNS-pinned requests.
- Reports in JSON and PDF (ReportLab); plain-text fallback if ReportLab is unavailable.
- Explicitly opted-in authentication for the exact isolated DVWA lab origin; credentials and session cookies are scan-scoped and excluded from logs and reports.
- Mock-based pytest tests; the test suite does not contact public websites.
- Docker image runs as a non-root user and has a Python-based health check.

Findings are possible indicators, not confirmed vulnerabilities. A response change or missing header alone does not establish exploitability.

## Technology

Python 3.10+, Flask, Requests, Beautiful Soup, Gunicorn, ReportLab, pytest, HTML, CSS, JavaScript, and Docker Compose.

## Architecture and workflow

1. The dashboard submits a JSON request to Flask.
2. The app validates the URL and request shape before accepting a scan.
3. Scanner HTTP requests revalidate names and addresses, connect to a validated IP, restrict redirects to the approved hostname, cap response size, and apply a socket inactivity timeout.
4. The optional crawler follows same-host links and stops after the page cap.
5. The scanner returns check results and crawl metadata; `report.py` builds a normalized report with possible/confirmed/error counts and explicit limitations.
6. The dashboard renders those results; exports reuse the displayed report rather than starting a second scan.

The local development server binds to `127.0.0.1`. Docker Compose publishes the app on `127.0.0.1:5000` only.

## OWASP Top 10:2021 coverage

The checks are narrow heuristics, not comprehensive category coverage.

| Category | Implemented check | Scope and caveats |
|---|---|---|
| A01 Broken Access Control | Conventional route response comparison | A public HTTP response does not prove access-control failure; no user roles or object-level authorization are verified. |
| A02 Cryptographic Failures | Sensitive-data, cookie, and transport indicators | Separates request cookie names from cookies set by the response; values are omitted. No cryptographic configuration or protocol audit. |
| A03 Injection | SQL error signatures on query/GET-form inputs and an inert reflected-marker check | Crawler records form action, method, and field names/types without values. POST fields are reported as not tested and are never submitted. Does not execute scripts or destructive SQL; findings require manual validation. |
| A04 Insecure Design | **Unsupported** | Not inferable from generic HTTP responses. |
| A05 Security Misconfiguration | Selected security headers and visible disclosure indicators | Not a complete configuration audit. |
| A06 Vulnerable and Outdated Components | Visible technology/version fingerprints | Fingerprints may be stale or incomplete and are not matched against a complete vulnerability database. |
| A07 Identification and Authentication Failures | **Unsupported / not tested** | Password-bearing form discovery is an informational login-surface indicator only, including during authenticated DVWA scans; an established session does not mean authentication controls were assessed. Discovery coverage is limited to crawled pages and common login paths. |
| A08 Software and Data Integrity Failures | **Unsupported** | No integrity, update, or supply-chain validation. |
| A09 Security Logging and Monitoring Failures | **Unsupported** | Cannot assess internal logging or alerting from ordinary responses. |
| A10 Server-Side Request Forgery | **Unsupported** | No SSRF payload testing. Outbound requests are restricted to globally routable addresses. |

The five categories listed as implemented have partial heuristic coverage only. No claim of complete OWASP Top 10 coverage is made.

## Requirements

- Python 3.10 or later.
- Docker Desktop / Docker Engine and Compose are optional.
- The scanner rejects localhost, private, reserved, and non-routable destinations by default. A separate opt-in DVWA lab Compose file configures one exact service origin and pinned private IP on an isolated Docker network.

## Install and run locally

From the repository directory:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000>. To stop the server, press `Ctrl+C`.

## Docker

```powershell
docker compose up --build
```

Open <http://127.0.0.1:5000>. The health check uses Python's standard library, so it does not depend on `curl` being installed in the image. Stop the service with `Ctrl+C`, or run `docker compose down` in another terminal.

For an image-only build:

```powershell
docker build -t owasp-scanner:local .
```

## Optional isolated DVWA lab

The standard Compose setup does not allow private targets. The lab override uses Compose v2.24 or newer. To run the included, deliberately vulnerable DVWA image in an isolated Docker network, use the lab override:

```powershell
docker compose -f docker-compose.yml -f docker-compose.dvwa.yml config
docker compose -f docker-compose.yml -f docker-compose.dvwa.yml up --build -d
```

The scanner and DVWA run only on a Docker-internal network with a fixed DVWA container IP. The lab override reads the private subnet and container addresses from a local `.env` file, which is ignored by Git and Docker build context rules. Before starting the lab, create `.env` in this format and replace the placeholders with an unused private subnet and distinct addresses inside it:

```text
SCANNER_LOCAL_LAB_SUBNET=<unused private subnet in CIDR notation>
SCANNER_CONTAINER_IP=<scanner address inside that subnet>
SCANNER_LOCAL_LAB_IP=<DVWA address inside that subnet>
```

Do not commit this file. A small fixed-route Nginx gateway publishes the dashboard and DVWA UI only on `127.0.0.1:5000` and `127.0.0.1:8080`; neither application container is directly published. Scanner lab access is opt-in and limited to `http://dvwa:80` resolving only to the configured DVWA address; other private IPs, ports, hosts, and redirect origins remain blocked. The gateway has fixed upstreams and does not accept a user-supplied proxy destination. The separate lab environment must not be used for other destinations. Open DVWA at <http://127.0.0.1:8080> and complete its local database setup if prompted.

Run a crawl from the scanner dashboard using `http://dvwa:80` with crawling enabled. For an authenticated lab scan, select **Authenticated DVWA lab scan**, then enter your DVWA credentials directly in the dashboard. Credentials are sent only to this local Flask instance and the exact configured DVWA origin; they are not logged or included in results/reports, and the fields are cleared after the scan. Never paste credentials into chat or put them in environment variables, URLs, source files, or reports. This option is available only when the lab override sets `SCANNER_LOCAL_LAB_AUTH_ENABLED=1`; it does not enable private-network scanning beyond the pinned DVWA service.

The scanner performs login solely to establish a session, then sends non-destructive quote markers to query parameters and GET forms and an inert HTML marker for reflection checks. It does not submit POST vulnerability forms, execute script, delay the database, modify files, or assess password policy/MFA/authorization. A07 remains not assessed (login-form discovery is informational). Only possible indicators are reported; manually verify findings. To stop the lab:

```powershell
docker compose -f docker-compose.yml -f docker-compose.dvwa.yml down
```

## Perform an authorized scan

Only enter a URL for an application you own or have explicit written permission to assess. Confirm the hostname and scope with the system owner before scanning. Do not use this tool against third-party sites, production systems without approval, or targets whose authorization is unclear.

Enter an absolute `http://` or `https://` URL in the dashboard. The scanner rejects local/private/reserved IP destinations by default, credentials embedded in URLs, unsupported schemes, and out-of-scope redirects/links. Only the isolated DVWA Compose override enables the exact pinned local lab destination. The crawl option is disabled by default and is limited to 20 discovered pages. The scan request is synchronous; large or slow sites may take time.

## Reports

- Use **Download JSON** or **Download PDF Report** after a scan. The dashboard exports the report already returned by `/scan`, so downloading does not repeat the scan.
- `POST /export/json` and `POST /export/pdf` accept `{ "report": <report object returned by /scan> }`.
- For compatibility, those export endpoints also accept `{ "url": "https://authorized-host.example", "crawl": false }` and run a new scan.
- If ReportLab is unavailable, the PDF route returns a plain-text report with a `.txt` filename.

Reports include the target, UTC generation time, pages and check counts, severity totals, individual results, evidence, affected URLs, remediation guidance, category coverage, limitations, and whether the scan used an authenticated or unauthenticated lab session. They do not contain usernames, passwords, or session cookies. All current detection signals are classified as possible, not confirmed.

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Dashboard |
| `GET` | `/health` | `{"status":"ok","version":"2.0.0"}` |
| `POST` | `/scan` | Validate and run a scan; returns a structured JSON report |
| `POST` | `/export/json` | Download a JSON report, or scan then export using the compatibility request |
| `POST` | `/export/pdf` | Download a PDF (or text fallback), or scan then export |
| `POST` | `/export` | Legacy alias for JSON export |

Scan request:

```json
{"url": "https://authorized-host.example", "crawl": false}
```

`url` must be a valid absolute HTTP(S) URL resolving only to globally routable addresses. `crawl` must be a JSON boolean. Invalid requests receive a JSON `error` message and an appropriate 4xx status. The app accepts at most 2 MB per JSON request and rejects new scans when its local scan slots are full.

For the opt-in lab only, `/scan` also accepts `{"url":"http://dvwa:80","crawl":true,"authenticated":true,"username":"...","password":"..."}`. Only submit this request from the local dashboard or an equally trusted local client; credentials are accepted only for the configured DVWA origin.

## Tests

```powershell
python -m pip install pytest
python -m pytest -q
```

Tests use mocks or Flask's test client and do not scan real websites.

## Known limitations

- All vulnerability detection is heuristic. Possible findings need manual verification; clean results do not prove a system is secure.
- The scanner covers only the specific checks listed above; A04, A07, A08, A09, and A10 are unsupported, and the remaining coverage is partial.
- A07 authentication controls are not tested: credentials are used only to establish an opt-in DVWA lab session. MFA, password quality, lockout, and session security require an authorized manual assessment.
- The crawler has a page limit but no configurable crawl-depth limit or JavaScript rendering.
- The HTTP timeout limits socket inactivity, not total elapsed request time; slow-drip responses may occupy a worker longer than the configured timeout.
- Crawl progress is not streamed; the dashboard receives results when the synchronous scan completes.
- The app is designed for local demonstration and does not provide user authentication, authorization, a job queue, or multi-instance coordination. Do not expose it to untrusted users.
- Private destinations are rejected by default. The opt-in DVWA lab exception depends on the isolated Docker network and fixed configured service address, and is not a general-purpose private-network scanning mode.

## Ethical use

Use only against systems you own or are explicitly authorized to assess. Obtain written authorization, follow the approved scope and rate limits, and stop if a target owner requests it. The operator is responsible for lawful and safe use.
