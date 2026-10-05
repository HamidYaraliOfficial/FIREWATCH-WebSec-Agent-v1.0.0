# FIREWATCH Web Security Agent

**Version:** 1.0.0  
**Purpose:** Authorized web application security assessment with strict scope controls, deterministic evidence collection, optional browser discovery, and pluggable ZAP/LLM integrations.

> **Authorization requirement:** Run FIREWATCH only against systems you own or have explicit permission to assess. The default policy rejects private/reserved targets unless `ALLOW_PRIVATE_TARGETS=true` is explicitly enabled. The scanner is intentionally non-destructive and does not ship exploit payloads or credential-stuffing logic.

## What is included

- FastAPI control plane and REST API
- PostgreSQL persistence (SQLite supported for local development/tests)
- DB-backed worker queue, so Redis/Celery are not required for the core product
- Scope and safety policy enforcement before every network action
- HTTP crawler with same-scope URL normalization and redirect isolation
- Optional Playwright browser discovery for JavaScript-rendered applications
- Deterministic security rule engine
- Evidence and confidence scoring
- Finding de-duplication
- HTML + JSON report generation
- React 19.3 dashboard built with Vite 8.x
- Optional ZAP Automation Framework adapter
- Local intentionally-insecure demo target for validation
- Unit/integration tests
- Docker Compose deployment

## Supported safe checks in 1.0.0

### HTTP / configuration
- Missing Content-Security-Policy
- Missing Strict-Transport-Security on HTTPS
- Missing X-Content-Type-Options
- Missing Referrer-Policy
- Missing Permissions-Policy
- Missing clickjacking protection (`X-Frame-Options` / CSP `frame-ancestors`)
- Server / framework banner disclosure
- Dangerous HTTP methods advertised by `Allow`
- HTTPS page with mixed-content subresources
- External redirects discovered in response headers

### Cookies and forms
- Missing Secure on cookies received over HTTPS
- Missing HttpOnly on session-like cookies
- Missing SameSite
- Password form submitted over HTTP
- Password forms without a CSRF-token indicator (flagged as a review candidate, not a confirmed CSRF vulnerability)

### CORS and API discovery
- Wildcard `Access-Control-Allow-Origin`
- Reflected Origin
- Wildcard CORS with credentials
- Common API/documentation endpoints linked from pages
- OpenAPI/Swagger/GraphQL endpoint candidates are inventoried, not exploited

### Information disclosure / discovery
- `robots.txt` and `sitemap.xml` inventory
- Source-map references
- Common backup/archive references exposed in HTML/JS (`.bak`, `.old`, `.zip`, `.tar`, `.sql` etc.) are reported as candidates only when actually linked/found in retrieved content

## Architecture

```text
                        +----------------------+
                        | React Dashboard      |
                        +----------+-----------+
                                   |
                                   v
                        +----------------------+
                        | FastAPI Control Plane |
                        +----------+-----------+
                                   |
                         creates Scan Job
                                   |
                                   v
                        +----------------------+
                        | PostgreSQL / SQLite   |
                        +----------+-----------+
                                   |
                          claims queued job
                                   |
                                   v
                     +-------------+--------------+
                     | FIREWATCH Worker           |
                     |                            |
                     | Scope -> Crawl -> Rules   |
                     |        -> Browser         |
                     |        -> Evidence        |
                     |        -> Report          |
                     +----------------------------+
                              |           |
                              v           v
                       Target system   Optional ZAP
```

## Requirements

- Python 3.12+ recommended
- Node.js 22+ recommended for the frontend
- PostgreSQL 16+ for production
- Chromium browser binaries if Playwright is enabled
- Docker Engine / Docker Compose for the containerized setup

The container setup pins the Playwright Python image to the 1.63 line and keeps the Python package version aligned with the browser image. Playwright's documentation explicitly recommends keeping the Docker image and Playwright package versions aligned. The current project uses React 19.3 and a Vite 8.x toolchain. SQLAlchemy is used in its current 2.0 style.

## Quick start — local

### Backend

```bash
cd backend
python -m venv .venv
# Windows
.venv\\Scripts\\activate
# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The backend defaults to SQLite for local use:

```text
DATABASE_URL=sqlite:///./firewatch.db
```

### Worker

In another terminal:

```bash
cd backend
# activate the same virtual environment
python -m app.worker
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

## Quick start — Docker Compose

```bash
docker compose up --build
```

Services:

- Frontend: `http://localhost:5173`
- API: `http://localhost:8000`
- OpenAPI docs: `http://localhost:8000/docs`
- PostgreSQL: `localhost:5432`

For optional ZAP support:

```bash
docker compose --profile zap up --build
```

## Local demo target

The repository includes `demo_target/`, a deliberately insecure but **local-only** application used to validate detections.

Run:

```bash
cd demo_target
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 9000
```

Then, for local development only, set:

```text
ALLOW_PRIVATE_TARGETS=true
```

Create a scan for:

```text
http://127.0.0.1:9000/
```

The demo exposes intentionally weak headers/cookie/form behavior so the scanner should produce findings.

## API example

Create a scan:

```bash
curl -X POST http://localhost:8000/api/v1/scans \\
  -H "Content-Type: application/json" \\
  -d '{
    "target_url": "http://127.0.0.1:9000/",
    "max_pages": 40,
    "max_depth": 4,
    "enable_browser": false,
    "passive_only": true,
    "respect_robots": true
  }'
```

Get scans:

```bash
curl http://localhost:8000/api/v1/scans
```

Get a report:

```bash
curl http://localhost:8000/api/v1/scans/<SCAN_ID>/report
```

## Environment variables

See `backend/.env.example`.

Important safety variables:

- `ALLOW_PRIVATE_TARGETS=false` by default
- `MAX_PAGES=100`
- `MAX_DEPTH=6`
- `REQUEST_TIMEOUT_SECONDS=15`
- `REQUEST_DELAY_MS=250`
- `MAX_CONCURRENCY=4`
- `RESPECT_ROBOTS=true`
- `ENABLE_BROWSER=false`
- `ENABLE_ZAP=false`

## Extension model

Security checks implement a small plugin contract. Add a class under `backend/app/rules/`, expose it from `backend/app/rules/registry.py`, and it will become available to the planner.

A rule receives a `ScanContext` and a `PageSnapshot`/`HTTPObservation`, then emits zero or more `FindingCandidate` records. The rule must never bypass `ScopePolicy`.

## Design principles

1. **Scope before network:** every outbound request is validated by the scope policy.
2. **Evidence before severity:** a finding needs observable evidence; hypotheses are explicitly marked.
3. **No destructive defaults:** no delete/update requests, credential attacks, arbitrary file writes, or exploit chains.
4. **Deterministic core:** the core scanner does not depend on an LLM.
5. **LLM-ready:** planner and analysis interfaces can be replaced with OpenAI-compatible or local model adapters later.
6. **Composable:** ZAP, Playwright and future scanners are adapters rather than hard dependencies.
7. **Auditable:** jobs, observations, findings, evidence and reports are persisted.

## Standards mapping

The product is designed around OWASP Web Security Testing Guide concepts and the OWASP Top 10, with API-specific inventory concepts inspired by OWASP API Security Top 10. Exact coverage is intentionally scoped to the safe, non-destructive rule set in this release.

## Security of FIREWATCH itself

- Do not expose the control-plane API directly to the public Internet without an authentication layer.
- Run worker containers as non-root where practical.
- Store target credentials outside the database; 1.0.0 does not accept arbitrary credential material through the scan API.
- Use a dedicated network egress policy for production worker nodes.
- Treat report contents as sensitive.
