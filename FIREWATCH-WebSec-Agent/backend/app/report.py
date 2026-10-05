from __future__ import annotations

from pathlib import Path
from typing import Iterable

from jinja2 import Environment, BaseLoader, select_autoescape

from .config import settings
from .models import Finding, Scan, Severity

TEMPLATE = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FIREWATCH Security Report - {{ scan.target_url }}</title>
<style>
body{font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif;margin:40px;background:#0b1020;color:#e9eefb}
.container{max-width:1100px;margin:auto}.card{background:#131a2b;border:1px solid #26314a;border-radius:14px;padding:20px;margin:16px 0}
h1{margin-bottom:4px} h2{margin-top:0} table{width:100%;border-collapse:collapse}th,td{padding:9px;border-bottom:1px solid #2a3550;text-align:left;vertical-align:top}
.badge{display:inline-block;padding:4px 9px;border-radius:999px;font-size:12px;font-weight:700}.critical{background:#7f1d1d}.high{background:#9a3412}.medium{background:#92400e}.low{background:#1d4ed8}.info{background:#475569}
small{color:#aab4cc}.finding{page-break-inside:avoid}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
</style>
</head>
<body><div class="container">
<h1>FIREWATCH Web Security Report</h1>
<small>Generated for authorized assessment only</small>
<div class="card"><h2>Scope</h2><div class="mono">{{ scan.target_url }}</div><p>Status: {{ scan.status.value }}</p></div>
<div class="card"><h2>Executive Summary</h2>
<table><tr><th>Severity</th><th>Count</th></tr>
{% for sev in severities %}<tr><td><span class="badge {{ sev.value }}">{{ sev.value|upper }}</span></td><td>{{ counts.get(sev.value,0) }}</td></tr>{% endfor %}
</table></div>
<div class="card"><h2>Findings</h2>
{% for f in findings %}
<div class="card finding">
<h3>{{ f.title }} <span class="badge {{ f.severity.value }}">{{ f.severity.value|upper }}</span></h3>
<p><b>Rule:</b> {{ f.rule_id }} &nbsp; <b>Confidence:</b> {{ '%.0f'|format(f.confidence*100) }}% &nbsp; <b>Risk:</b> {{ f.risk_score }}</p>
<p><b>Endpoint:</b> <span class="mono">{{ f.endpoint }}</span></p>
<p>{{ f.description }}</p><p><b>Impact:</b> {{ f.impact }}</p><p><b>Evidence:</b> {{ f.evidence_summary }}</p><p><b>Remediation:</b> {{ f.remediation }}</p>
{% if f.references %}<p><b>References:</b> {{ f.references|join(', ') }}</p>{% endif %}
</div>
{% endfor %}
</div>
</div></body></html>
"""


def render_html(scan: Scan, findings: Iterable[Finding], output_path: str) -> None:
    findings = list(findings)
    counts = {sev.value: sum(1 for f in findings if f.severity == sev) for sev in Severity}
    env = Environment(loader=BaseLoader(), autoescape=select_autoescape(["html", "xml"]))
    html = env.from_string(TEMPLATE).render(scan=scan, findings=findings, counts=counts, severities=list(Severity))
    Path(output_path).write_text(html, encoding="utf-8")


def render_json(scan: Scan, findings: Iterable[Finding], output_path: str) -> None:
    import json
    findings = list(findings)
    payload = {
        "scan": {"id": scan.id, "target_url": scan.target_url, "status": scan.status.value},
        "findings": [
            {
                "id": f.id, "rule_id": f.rule_id, "title": f.title, "severity": f.severity.value,
                "confidence": f.confidence, "risk_score": f.risk_score, "endpoint": f.endpoint,
                "description": f.description, "impact": f.impact, "remediation": f.remediation,
                "references": f.references, "evidence_summary": f.evidence_summary,
            } for f in findings
        ]
    }
    Path(output_path).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
