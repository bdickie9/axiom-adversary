from __future__ import annotations

import time
from typing import Any

from .proofs import SettlementProof, BountyProof, FailureArtifact


class SettlementMemory:
    """Append-only chain of SettlementProofs. Policy is pure function of the chain."""

    def __init__(self) -> None:
        self.proofs: list[SettlementProof] = []
        self.bounties: list[BountyProof] = []

    def head_hash(self) -> str | None:
        return self.proofs[-1].digest() if self.proofs else None

    def append(self, proof: SettlementProof) -> None:
        expected = self.head_hash()
        if proof.prev_hash != expected:
            raise ValueError("hash link broken")
        self.proofs.append(proof)


def on_settlement(
    event: dict[str, Any],
    *,
    session_id: str,
    product: str,
    seat: dict[str, str],
    memory: SettlementMemory,
    reserve_fraction: float = 0.05,
    min_reserve_cents: int = 500,
) -> BountyProof:
    """
    Only call after webhook signature verification and paid confirmation.
    """
    if event.get("type") not in ("checkout.session.completed", "invoice.paid"):
        raise ValueError("unsupported event type")

    data = event.get("data", {}).get("object", {})
    if data.get("payment_status") != "paid" and event.get("type") != "invoice.paid":
        raise ValueError("not paid")

    amount = int(data.get("amount_total") or data.get("amount_paid") or 0)
    if amount <= 0:
        raise ValueError("zero amount")

    proof = SettlementProof(
        event_id=event["id"],
        session_id=session_id,
        amount=amount,
        currency=data.get("currency", "usd"),
        product=product,
        seat=seat,
        ts=time.time(),
        prev_hash=memory.head_hash(),
    )
    memory.append(proof)

    reserved = max(min_reserve_cents, int(amount * reserve_fraction))
    bounty = BountyProof(
        settlement_hash=proof.digest(),
        reserved_cents=reserved,
        expires_at=time.time() + 7 * 86400,
        prev_hash=proof.prev_hash,
    )
    memory.bounties.append(bounty)
    return bounty


def verify_claim(artifact: FailureArtifact, memory: SettlementMemory) -> bool:
    """
    Mechanical check. Extend with specific invariant recomputes.
    Returns True only if the artifact points at a known settlement
    and its evidence demonstrates a mismatch that can be re-derived
    from the chain.
    """
    known = {p.digest() for p in memory.proofs}
    if artifact.settlement_hash not in known:
        return False

    # Placeholder invariants. Real implementation recomputes policy
    # or refund state from the chain and compares to evidence.
    if artifact.invariant == "refund_not_reflected":
        return "refund_id" in artifact.evidence
    if artifact.invariant == "stale_demand":
        return artifact.evidence.get("age_seconds", 0) > 86400
    if artifact.invariant == "missing_refusal":
        return artifact.evidence.get("required") is True
    return False
