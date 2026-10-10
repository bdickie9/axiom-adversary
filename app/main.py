"""
Example FastAPI service that receives already-verified Stripe events
and emits BountyProofs.

In production, signature verification happens before this handler.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Any

from axiom_adversary import on_settlement, verify_claim, SettlementMemory, FailureArtifact

app = FastAPI(title="Axiom Adversary")
memory = SettlementMemory()


class ClaimRequest(BaseModel):
    settlement_hash: str
    invariant: str
    evidence: dict[str, Any]


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "proofs": str(len(memory.proofs)), "bounties": str(len(memory.bounties))}


@app.post("/webhooks/stripe")
def stripe_webhook(event: dict[str, Any]) -> dict[str, Any]:
    """
    Expects an already-verified event. In MIDAS this runs after
    webhook_verify.py succeeds.
    """
    try:
        # Extract session / product / seat from metadata in a real integration.
        data = event.get("data", {}).get("object", {})
        session_id = data.get("id", "")
        product = data.get("metadata", {}).get("product", "unknown")
        seat = {
            "trade": data.get("metadata", {}).get("trade", ""),
            "city": data.get("metadata", {}).get("city", ""),
        }
        bounty = on_settlement(
            event,
            session_id=session_id,
            product=product,
            seat=seat,
            memory=memory,
        )
        return {"bounty_hash": bounty.digest(), "reserved_cents": bounty.reserved_cents}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/claims")
def claim(req: ClaimRequest) -> dict[str, Any]:
    artifact = FailureArtifact(
        settlement_hash=req.settlement_hash,
        invariant=req.invariant,
        evidence=req.evidence,
        claimed_at=__import__("time").time(),
    )
    ok = verify_claim(artifact, memory)
    return {"accepted": ok, "artifact_hash": artifact.digest()}


@app.get("/bounties")
def list_bounties() -> list[dict[str, Any]]:
    return [
        {
            "hash": b.digest(),
            "settlement_hash": b.settlement_hash,
            "reserved_cents": b.reserved_cents,
            "expires_at": b.expires_at,
        }
        for b in memory.bounties
    ]
