from __future__ import annotations

from dataclasses import dataclass, asdict
from hashlib import sha256
import json
import time
from typing import Any


def _digest(obj: dict[str, Any]) -> str:
    blob = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    return sha256(blob.encode()).hexdigest()


@dataclass(frozen=True)
class SettlementProof:
    event_id: str
    session_id: str
    amount: int
    currency: str
    product: str
    seat: dict[str, str]
    ts: float
    prev_hash: str | None = None

    def digest(self) -> str:
        return _digest(asdict(self))


@dataclass(frozen=True)
class BountyProof:
    settlement_hash: str
    reserved_cents: int
    expires_at: float
    prev_hash: str | None = None

    def digest(self) -> str:
        return _digest(asdict(self))


@dataclass(frozen=True)
class FailureArtifact:
    settlement_hash: str
    invariant: str  # e.g. "refund_not_reflected", "stale_demand", "missing_refusal"
    evidence: dict[str, Any]
    claimed_at: float

    def digest(self) -> str:
        return _digest(asdict(self))

    def matches(self, settlement_hash: str) -> bool:
        return self.settlement_hash == settlement_hash
