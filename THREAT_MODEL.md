# Threat model — potlatch

A debtor disclaims the debt — the IOU is dual-signed; issuance alone doesn't bind, but the pending record is on the book. A creditor inflates the debt — the body is signed at issuance; tampering breaks both signatures. Invocations are fabricated — each is debtor-signed and bound to a specific IOU. Settlement exceeds balance — refused at the API. A default is erased — defaults are committed events on a hash-chained book. Balances are manipulated — they are derived from history, never stored.

## What this crate guarantees

- Debt binds both parties — creditor signs issuance, debtor signs acceptance.
- Settlement burns signed invocations bound to the specific IOU; over-settlement refuses.
- Balances and defaults are derived from the hash-chained book, never stored.

## What it does not guarantee

- Protection against a verifier who never calls `verify()`.
- Integrity of inputs produced by other systems — this crate verifies
  signatures and chains over what it is given; garbage that verifies is
  still garbage.
