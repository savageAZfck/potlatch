# SPEC — potlatch (mind economy)

## Instruments

`Iou` — dual-signed debt:

```json
{
  "id": "sha256", "creditor": "pubkey", "debtor": "pubkey",
  "treaty": "authorizing treaty id", "resource": "compute-seconds|…",
  "amount": 0, "due": "epoch or null", "ts": 0,
  "creditor_signature": "…", "debtor_signature": "…"
}
```

Creditor signs at `issue`; debtor countersigns the same body at
`accept`. Debt binds both.

`Invocation` — debtor-signed work record `{ id, iou, worker, units,
ts, signature }`; settlement burns these.

`Settlement` — creditor-signed `{ id, iou, invocations[], units, ts,
signature }` reducing the balance.

## Book

`Book` — hash-chained `Event`s: `Issue`, `Accept`, `Invoke`, `Settle`,
`Default`. `verify()` checks linkage + every embedded signature.

## Semantics

- `settle(creditor, iou, inv_ids)` — settler must be the creditor;
  each invocation must target this IOU; total ≤ remaining balance
  (`OverSettled` otherwise).
- `declare_default(creditor, iou, reason)` — creditor-only, permanent.
- `balance(iou)` = face − Σ settled units — **derived, never stored**.
- `obligations(debtor)` — outstanding balances by IOU id.
- `defaults(debtor)` — the credit report.
- `accept` may only occur once and only by the named debtor; the
  pending `Issue` record stays on the book — history is append-only.

## Invariants

- No signature, no debt; no debtor signature, no obligation.
- Repayment is tied to real invocations, not promises.
- Defaults cannot be erased — only offset by settled history.
