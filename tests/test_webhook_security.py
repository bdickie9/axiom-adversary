import hashlib
import hmac
import json
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from app import main
from axiom_adversary import SettlementMemory, on_settlement


SECRET = "whsec_offline_regression_fixture"


def event(amount=10000):
    return {"id":"evt_test", "type":"checkout.session.completed", "data":{"object":{
        "id":"cs_test", "payment_status":"paid", "amount_total":amount, "currency":"usd",
        "metadata":{"product":"test"}}}}


def signature(body, timestamp=None):
    timestamp = int(time.time()) if timestamp is None else timestamp
    digest = hmac.new(SECRET.encode(), str(timestamp).encode()+b"."+body, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={digest}"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(main, "memory", SettlementMemory())
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", SECRET)
    return TestClient(main.app)


def test_missing_configuration_is_unavailable(client, monkeypatch):
    monkeypatch.delenv("STRIPE_WEBHOOK_SECRET")
    assert client.post("/webhooks/stripe", json=event()).status_code == 503
    assert not main.memory.proofs


@pytest.mark.parametrize("mode", ["unsigned", "invalid", "expired", "tampered"])
def test_bad_signatures_cannot_create_proofs(client, mode):
    body = json.dumps(event()).encode()
    header = signature(body)
    if mode == "unsigned": header = ""
    if mode == "invalid": header = "t=1,v1=bad"
    if mode == "expired": header = signature(body, int(time.time())-1000)
    if mode == "tampered": body += b" "
    assert client.post("/webhooks/stripe", content=body, headers={"stripe-signature":header}).status_code == 400
    assert not main.memory.proofs


def test_verified_retry_returns_same_bounty(client):
    body = json.dumps(event()).encode()
    headers = {"stripe-signature":signature(body)}
    first = client.post("/webhooks/stripe", content=body, headers=headers)
    second = client.post("/webhooks/stripe", content=body, headers=headers)
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    assert len(main.memory.proofs) == len(main.memory.bounties) == 1


def record(memory, payload=None, **kwargs):
    return on_settlement(event() if payload is None else payload, session_id="cs_test", product="test", seat={}, memory=memory, **kwargs)


def test_concurrent_retries_are_idempotent():
    memory = SettlementMemory()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: record(memory), range(40)))
    assert len({result.digest() for result in results}) == 1
    assert len(memory.proofs) == len(memory.bounties) == 1


def test_conflicting_event_id_cannot_append_another_proof():
    memory = SettlementMemory()
    record(memory)
    with pytest.raises(ValueError, match="identity conflict"):
        record(memory, event(20000))
    assert len(memory.proofs) == len(memory.bounties) == 1


def test_small_payment_cannot_overfund_the_reserve():
    assert record(SettlementMemory(), event(100)).reserved_cents == 100


@pytest.mark.parametrize("amount", [True, "100", 0, -1, 1.5])
def test_invalid_amounts_do_not_mutate_memory(amount):
    memory = SettlementMemory()
    with pytest.raises(ValueError): record(memory, event(amount))
    assert not memory.proofs


@pytest.mark.parametrize("fraction", [-0.1, 1.1, float("nan"), float("inf"), True])
def test_invalid_reserve_policy_does_not_mutate_memory(fraction):
    memory = SettlementMemory()
    with pytest.raises(ValueError): record(memory, reserve_fraction=fraction)
    assert not memory.proofs


def test_invoice_type_alone_is_not_paid_evidence():
    payload = event()
    payload["type"] = "invoice.paid"
    with pytest.raises(ValueError, match="not paid"): record(SettlementMemory(), payload)


def test_paid_invoice_uses_amount_paid():
    payload = event()
    payload["type"] = "invoice.paid"
    payload["data"]["object"].update(paid=True, status="paid", amount_paid=2000)
    assert record(SettlementMemory(), payload).reserved_cents == 500
