"""
Example FastAPI service that verifies Stripe signatures before recording events.
In-memory proof storage is for local evaluation, not production settlement.
"""

import os
import json
import stripe

from fastapi import FastAPI, HTTPException, Request
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
async def stripe_webhook(request: Request) -> dict[str, Any]:
    secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    if not secret:
        raise HTTPException(status_code=503, detail="Webhook verification is not configured")
    try:
        payload = await request.body()
        stripe.Webhook.construct_event(
            payload, request.headers.get("stripe-signature", ""), secret, tolerance=300
        )
        # Keep the engine independent of SDK resource-object versions.
        event = json.loads(payload)
    except (ValueError, stripe.SignatureVerificationError):
        raise HTTPException(status_code=400, detail="Invalid webhook signature or payload")
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
    except (ValueError, KeyError, TypeError, AttributeError):
        raise HTTPException(status_code=400, detail="Invalid settlement event")


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
