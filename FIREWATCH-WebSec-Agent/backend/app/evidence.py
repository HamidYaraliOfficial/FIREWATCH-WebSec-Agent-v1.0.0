from __future__ import annotations

from dataclasses import dataclass
import hashlib

from .rules.base import FindingCandidate


@dataclass(frozen=True)
class NormalizedFinding:
    candidate: FindingCandidate
    dedupe_key: str


def normalize_candidate(candidate: FindingCandidate) -> NormalizedFinding:
    basis = "|".join([candidate.rule_id, candidate.endpoint, candidate.title])
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:32]
    return NormalizedFinding(candidate, digest)
