from __future__ import annotations

import time
from typing import Any

from .proofs import (
    SettlementProof,
    BountyProof,
    FailureArtifact,
    DemandProof,
    RefusalProof,
    RefundRecord,
)


class SettlementMemory:
    """Append-only chain. Policy and claims are pure functions of the proofs."""

    def __init__(self) -> None:
        self.proofs: list[SettlementProof] = []
        self.bounties: list[BountyProof] = []
        self.demands: list[DemandProof] = []
        self.refusals: list[RefusalProof] = []
        self.refunds: list[RefundRecord] = []

    def head_hash(self) -> str | None:
        return self.proofs[-1].digest() if self.proofs else None

    def append(self, proof: SettlementProof) -> None:
        expected = self.head_hash()
        if proof.prev_hash != expected:
            raise ValueError("hash link broken")
        self.proofs.append(proof)

    def record_demand(self, demand: DemandProof) -> None:
        self.demands.append(demand)

    def record_refusal(self, refusal: RefusalProof) -> None:
        self.refusals.append(refusal)

    def record_refund(self, refund: RefundRecord) -> None:
        self.refunds.append(refund)


def on_settlement(
    event: dict[str, Any],
    *,
    session_id: str,
    product: str,
    seat: dict[str, str],
    memory: SettlementMemory,
    demand_hash: str | None = None,
    reserve_fraction: float = 0.05,
    min_reserve_cents: int = 500,
) -> BountyProof:
    """Only call after webhook signature verification and paid confirmation."""
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
        demand_hash=demand_hash,
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


def _find_settlement(memory: SettlementMemory, digest: str) -> SettlementProof | None:
    for p in memory.proofs:
        if p.digest() == digest:
            return p
    return None


def _demand_for(settlement: SettlementProof, memory: SettlementMemory) -> DemandProof | None:
    if not settlement.demand_hash:
        return None
    for d in memory.demands:
        if d.digest() == settlement.demand_hash:
            return d
    return None


def _refund_applied(settlement: SettlementProof, memory: SettlementMemory) -> bool:
    """True if a refund record exists that covers this settlement's event."""
    for r in memory.refunds:
        if r.charge_id == settlement.event_id and r.amount > 0:
            return True
    return False


def _refusal_covers(settlement: SettlementProof, memory: SettlementMemory, attempted: str) -> bool:
    for r in memory.refusals:
        if r.attempted == attempted and r.external_ref == settlement.event_id:
            return True
    return False


def verify_claim(artifact: FailureArtifact, memory: SettlementMemory) -> bool:
    """
    Recomputes state from the proof chain. Accepts only when the chain
    itself demonstrates the claimed mismatch.
    """
    settlement = _find_settlement(memory, artifact.settlement_hash)
    if settlement is None:
        return False

    if artifact.invariant == "refund_not_reflected":
        refund_id = artifact.evidence.get("refund_id")
        if not refund_id:
            return False
        matching = next((r for r in memory.refunds if r.refund_id == refund_id), None)
        if matching is None or matching.charge_id != settlement.event_id:
            return False
        # Claim succeeds only if the refund exists but has not been applied
        # to the chain's view of this settlement.
        return not _refund_applied(settlement, memory)

    if artifact.invariant == "stale_demand":
        demand = _demand_for(settlement, memory)
        if demand is None:
            return False
        age = settlement.ts - demand.ts
        return age > 86400

    if artifact.invariant == "missing_refusal":
        attempted = artifact.evidence.get("attempted")
        if not attempted:
            return False
        # Required when a demand was older than the window or an external failure is recorded.
        demand = _demand_for(settlement, memory)
        required = demand is not None and (settlement.ts - demand.ts) > 86400
        if not required:
            return False
        return not _refusal_covers(settlement, memory, attempted)

    return False
