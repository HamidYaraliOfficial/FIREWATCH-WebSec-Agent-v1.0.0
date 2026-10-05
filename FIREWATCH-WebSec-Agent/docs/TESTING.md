# Testing Guide

## Unit tests

```bash
cd backend
pytest -q
```

## Local end-to-end test

1. Start `demo_target` on `127.0.0.1:9000`.
2. Set `ALLOW_PRIVATE_TARGETS=true` in the backend environment.
3. Start the backend and worker.
4. Queue a scan from the dashboard.
5. Review the generated findings and report.

Expected findings include missing security headers, insecure cookie attributes after visiting `/set-cookie`, mixed content, and the password-form CSRF review candidate.

## Production-like smoke test

Start PostgreSQL + backend + worker with Docker Compose and scan an authorized staging application. Keep `ALLOW_PRIVATE_TARGETS=false` unless the worker is intentionally operating within a controlled private network.
