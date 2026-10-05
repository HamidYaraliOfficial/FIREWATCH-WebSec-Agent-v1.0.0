from app.crawler import PageSnapshot
from app.http_client import HTTPObservation
from app.models import Severity
from app.rules.registry import run_rules


def snapshot(url="https://example.com/"):
    obs = HTTPObservation(
        requested_url=url,
        final_url=url,
        status_code=200,
        headers={"server": "Example/1.0", "set-cookie": "session=abc"},
        body='<html><head><title>T</title></head><body><form><input type="password" name="password"></form><script src="http://cdn.example/x.js"></script></body></html>',
        elapsed_ms=10,
        content_type="text/html",
        body_sha256="x",
    )
    return PageSnapshot(url, 0, obs, "T", ["https://example.com/"], [{"action": url, "method": "post", "inputs": [{"name": "password", "type": "password"}]}], [], ["http://cdn.example/x.js"])


def test_rules_emit_expected_candidates():
    findings = run_rules(snapshot())
    ids = {f.rule_id for f in findings}
    assert "FW-HTTP-001" in ids
    assert "FW-HTTP-002" in ids
    assert "FW-CONTENT-001" in ids
    assert "FW-COOKIE-002" in ids
