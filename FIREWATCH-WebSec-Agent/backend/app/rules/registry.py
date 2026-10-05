from __future__ import annotations

from .base import FindingCandidate
from .content_checks import run_content_rules
from .cookie_checks import run_cookie_rules
from .cors import run_cors_rules
from .form_checks import run_form_rules
from .header_checks import run_header_rules
from ..crawler import PageSnapshot


RULES = [
    run_header_rules,
    run_cookie_rules,
    run_content_rules,
    run_form_rules,
    run_cors_rules,
]


def run_rules(page: PageSnapshot) -> list[FindingCandidate]:
    results: list[FindingCandidate] = []
    for rule in RULES:
        results.extend(rule(page))
    return results
