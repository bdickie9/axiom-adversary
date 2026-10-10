import time
from axiom_adversary import on_settlement, verify_claim, SettlementMemory, FailureArtifact


def test_settlement_emits_bounty():
    memory = SettlementMemory()
    event = {
        "id": "evt_1",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_1",
                "payment_status": "paid",
                "amount_total": 19900,
                "currency": "usd",
            }
        },
    }
    bounty = on_settlement(
        event,
        session_id="cs_1",
        product="metro-permit-leads",
        seat={"trade": "roofing", "city": "Minneapolis"},
        memory=memory,
    )
    assert len(memory.proofs) == 1
    assert bounty.reserved_cents == 995  # 5% of 19900
    assert bounty.settlement_hash == memory.proofs[0].digest()


def test_claim_requires_matching_settlement():
    memory = SettlementMemory()
    event = {
        "id": "evt_2",
        "type": "checkout.session.completed",
        "data": {"object": {"id": "cs_2", "payment_status": "paid", "amount_total": 10000}},
    }
    on_settlement(event, session_id="cs_2", product="x", seat={}, memory=memory)
    art = FailureArtifact(
        settlement_hash=memory.proofs[0].digest(),
        invariant="refund_not_reflected",
        evidence={"refund_id": "re_1"},
        claimed_at=time.time(),
    )
    assert verify_claim(art, memory) is True

    bad = FailureArtifact(
        settlement_hash="not_a_real_hash",
        invariant="refund_not_reflected",
        evidence={"refund_id": "re_1"},
        claimed_at=time.time(),
    )
    assert verify_claim(bad, memory) is False
