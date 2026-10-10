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

Drop the webhook handler into an existing FastAPI service (e.g. MIDAS) after signature verification. Or run this as a thin sidecar that receives already-verified events.

See `src/axiom_adversary/` for the core types and `app/main.py` for the example service.

## Status

Design + reference implementation. Live settlement requires a verified Stripe webhook on a production host. Current MIDAS host returns 402 (deployment disabled).
