# Axiom Adversary

Settlement-funded adversarial bounty for closed commercial revenue loops.

Every verified paid settlement automatically carves out a reserved fraction and publishes it as a public bounty. Anyone can claim the bounty by submitting a verifiable FailureArtifact that proves a concrete invariant was broken in the same loop.

## Why it exists

Autonomous systems that touch real money invent private records of success. Those records drift. Axiom Adversary makes the act of settling itself fund an open, mechanical audit of the loop that just settled. The operator cannot suppress the bounty; it is emitted by the settlement.

## Hard gates

- Only a webhook-verified Stripe event with `payment_status=paid` (or equivalent) can create a SettlementProof.
- The reserved bounty amount is a pure function of that settlement.
- Claims are accepted only when the FailureArtifact recomputes a mismatch against the same hash chain.
- No model judgment. No simulated checkouts. No discretionary treasury.

## Integration

The example HTTP endpoint verifies the raw request body with Stripe's SDK and
`STRIPE_WEBHOOK_SECRET`. Missing configuration returns 503; invalid or expired
signatures return 400. Set the secret through the hosting environment, never in git.
Internal integrations may call `on_settlement` only after signature verification.

Repeated event IDs return the original bounty within one process; conflicting
payloads are rejected. The reserve cannot exceed the payment amount. This is an
in-memory reference: event deduplication does not survive restarts or coordinate
multiple workers. Production requires durable transactions and unique event IDs.

See `src/axiom_adversary/` for the core types and `app/main.py` for the example service.

## Status

Design + reference implementation. Live settlement requires a verified Stripe webhook on a production host. Current MIDAS host returns 402 (deployment disabled).

Offline tests: `PYTHONPATH=src:. python -m pytest -q tests` (install `pytest` and
`httpx` alongside `requirements.txt`). Tests use synthetic signatures and no payments.
