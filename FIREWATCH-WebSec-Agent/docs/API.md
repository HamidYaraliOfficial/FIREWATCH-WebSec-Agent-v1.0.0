# API Reference

## POST /api/v1/scans

Queues a scan after scope validation.

Request:

```json
{
  "target_url": "https://example.com/",
  "max_pages": 100,
  "max_depth": 6,
  "request_delay_ms": 250,
  "max_concurrency": 4,
  "enable_browser": false,
  "enable_zap": false,
  "passive_only": true,
  "respect_robots": true,
  "exclusions": ["/logout", "/delete"]
}
```

## GET /api/v1/scans

Returns recent scans.

## GET /api/v1/scans/{id}

Returns status and counts.

## GET /api/v1/scans/{id}/findings

Returns findings ordered by risk score.

## GET /api/v1/scans/{id}/report?format=html

Returns the persisted HTML report. Use `format=json` for machine-readable output.
