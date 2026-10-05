# Extending FIREWATCH

## Add a rule

1. Create a module in `backend/app/rules/`.
2. Accept a `PageSnapshot`.
3. Emit `FindingCandidate` instances.
4. Use a unique `FW-*` rule identifier.
5. Keep confidence honest and evidence observable.
6. Register the function in `backend/app/rules/registry.py`.
7. Add a unit test.

Example:

```python
from app.models import Severity
from app.rules.base import FindingCandidate


def run_my_rule(page):
    if "needle" not in page.observation.body:
        return []
    return [FindingCandidate(
        rule_id="FW-CUSTOM-001",
        title="Example finding",
        severity=Severity.LOW,
        confidence=0.8,
        endpoint=page.url,
        description="...",
        impact="...",
        remediation="...",
        evidence_summary="needle was observed",
    )]
```

## Add an LLM planner

Implement a class matching `PlannerProtocol`. It should output structured decisions only. Any action must still pass through `ScopePolicy`.
