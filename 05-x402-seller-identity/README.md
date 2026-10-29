# 05: an x402 seller that asks who the agent works for

```bash
cargo run -p ex05-x402-seller-identity
cargo test -p ex05-x402-seller-identity
```

An x402 seller gets paid by an agent. Payment alone doesn't say whose agent
it is, or whether its owner meant it to buy this. This example adds that check
to an [x402-axum](https://crates.io/crates/x402-axum) seller with
[aethel-auth](https://docs.rs/aethel-auth), and refuses the agent before
serving it.

- **The owner** signs a `Delegation` for its agent's key, at this seller only.
  It lists the routes the agent may call, a ceiling per call, a total per day,
  a price above which the owner must approve, and an expiry.
- **The agent** signs a `LoginProof` for each request. It's bound to the
  method, the path, the body and the x402 payment header, so it can't be
  replayed or moved onto a different payment.
- **The seller** checks both with aethel-auth's verifier API, and keeps its own
  list of owners it recognises and keys it has seen revoked.

Keys are ML-DSA-65 (FIPS 204). The owner and the agent hold their own keys,
and the seller verifies from public bytes alone. 0x307 never holds your keys
or your identity, and no 0x307 service is in this flow.

## Where the check sits

The gate is an ordinary axum middleware, added **inside** x402-axum's layer:

```rust
get(premium)
    .layer(axum::middleware::from_fn_with_state(policy, aethel_gate)) // inner
    .layer(x402.with_price_tag(price_tag))                           // outer
```

- An unpaid request still gets x402's `402` with the price, so crawlers and
  new clients see a normal x402 endpoint.
- A paid request reaches the gate after the facilitator has **verified** the
  payment and before anything **settles**. By default x402-axum settles only
  when the handler returns success, so an agent the gate refuses with `403` is
  not charged. The tests count settlements to prove it.
- **Don't combine this with `settle_before_execution()`.** Then the payment
  settles first and the refusal comes after the charge. A test asserts exactly
  that, so this warning stays true.

## What the seller checks

`src/gate.rs`, in order:

1. The agent's proof verifies for this request and this payment, and its nonce
   hasn't been used (`verify_login_for_request`).
2. The delegation is from an owner this seller recognises, neither key is
   revoked here, it's for this seller and still valid, it names the agent that
   just proved itself, it lists this route, and the price is within the
   per-call ceiling (`authorise`). The price is always passed as an amount.
3. Above the owner's threshold, the owner approved this exact request under
   this delegation (`check_approval`, signed with `Holder::approve`).
4. The day's total stays under the delegation's limit. aethel-auth hands this
   back to the seller in `RemainingObligations`, because only the seller knows
   what was spent.

Revocations arrive at `POST /aethel/revocations` as signed statements. An owner
that revokes its own key ends every delegation it gave at this seller.

## What this example does not do

- **The facilitator is fake.** It's in-process, says every payment is valid
  and counts settlements. A real seller points `X402Middleware` at a
  facilitator URL. Example 04 shows the payer's side of the payment.
- **The clock and keys are fixed** so every run prints the same thing.
- **Nonces, running totals and revocations live in memory.** A real seller
  keeps them somewhere that survives a restart and is shared across instances.
- **Headers are large.** A delegation is about 10 KB as JSON and a proof about
  7 KB, since post-quantum keys and signatures are big. That's over nginx's
  default 8 KB limit for one header line, so behind a proxy you may need to
  raise it.
- **No key rotation.** aethel-auth has succession statements; this example
  doesn't use them.
- **The payment isn't tied to the owner's wallet.** The proof binds the agent's
  identity to this payment header, not to the paying address.

## Status

**Not independently audited.** aethel-auth is a Preview crate, and its 0.2.0
API came out of an internal review of 0.1.0. Read the
[aethel-auth docs](https://docs.rs/aethel-auth) for what it does and doesn't
cover. Built against `aethel-auth 0.2.0`, `aethel-core 0.7.5` and
`x402-axum 2.0.2`, as pinned in this repository's `Cargo.lock`.
