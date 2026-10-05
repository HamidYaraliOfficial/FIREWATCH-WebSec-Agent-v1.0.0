# FIREWATCH Architecture

## Control plane

FastAPI exposes the project/scan/report API and is intentionally separated from actual target interaction.

## Persistence

SQLAlchemy 2.0 models persist:

- projects
- scans
- pages
- observations
- findings
- evidence
- reports

The worker claims queued jobs from the same datastore. PostgreSQL is the recommended production database. SQLite is supported for single-worker local development.

## Worker pipeline

```text
Queued Scan
   |
   +--> Scope validation
   |
   +--> Robots policy (optional)
   |
   +--> HTTP crawl
   |       |
   |       +--> page snapshot
   |       +--> rule engine
   |       +--> same-scope URL discovery
   |
   +--> Optional browser discovery
   |
   +--> Evidence normalization
   |
   +--> Deduplication
   |
   +--> Risk scoring
   |
   +--> Report creation
   |
   +--> Completed
```

## Rule engine

Rules are deterministic and emit candidate findings. Each candidate has:

- rule id
- title
- severity
- confidence
- endpoint
- evidence
- remediation
- standards references

## LLM boundary

`PlannerProtocol` can later be backed by an LLM. The LLM receives structured summaries rather than raw secret material. Tool execution remains subject to scope checks.

## Network safety boundary

The only code allowed to perform target HTTP requests is the HTTP client service. It requires a valid `ScopePolicy` for each request. Redirects are not followed automatically across hosts.
