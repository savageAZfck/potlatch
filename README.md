# potlatch

**The mind economy — signed compute IOUs between sovereign organisms, settled against real treaty invocations on a hash-chained book.**

Potlatch: the gift economy where standing is built by what you give and proven by what you settle.

## Why this exists

Economics needs scarcity and property. A cloud API has neither — the vendor owns the meter, the pricing, and the kill switch. Between sovereign organisms, compute is *owned*: organism A spends its GPU-seconds running work for organism B, and the cost is real because A's own ledger attests it. Potlatch makes that debt a first-class, verifiable artifact.

## The instruments

- **`Iou`** — dual-signed debt: creditor issues, debtor countersigns. Debt requires consent from both sides. Always references the treaty authorizing the relationship.
- **`Invocation`** — the debtor's signed record of work actually performed. Settlement burns invocations, so repayment tracks real usage, not promises.
- **`Settlement`** — creditor-signed reduction of debt; refuses to burn invocations aimed at a different IOU or to settle more than the remaining balance.
- **`Default`** — creditor-declared, permanent. An organism's credit is its history, and it can't forge a better one without breaking the chain.

## The book

Every issuance, acceptance, invocation, settlement, and default is a hash-chained event carrying its signatures. **Balances are derived, never stored** — `balance()`, `obligations()`, and `defaults()` compute over history, so they can't drift from it. `verify()` checks linkage and every signature, fully offline.

## Try it

```bash
cargo run --example economy
cargo test
```

## Pair with

- `wolakota` — the treaties that authorize economic relationships
- `sovereign_ledger` — the chain discipline the book inherits
- `kola` — a third organism can witness book heads, so debt history can't shrink
- `germline` — offspring start with zero debt and their own credit to earn
