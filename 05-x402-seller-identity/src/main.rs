//! An x402 seller that refuses an agent before serving it, unless the agent's
//! owner delegated this purchase to it.
//!
//! Run: `cargo run -p ex05-x402-seller-identity`
//!
//! x402-axum handles the payment. A small axum middleware inside it handles
//! identity with `aethel-auth`:
//!
//! * the owner signs a `Delegation` naming its agent's key, this seller, the
//!   route, a per-call ceiling, a daily total, an approval threshold and an
//!   expiry;
//! * the agent signs a `LoginProof` bound to this one request, including its
//!   payment header, so the proof cannot be moved onto another payment;
//! * the seller checks both, and refuses with 403. x402-axum settles only
//!   after the handler succeeds, so a refused agent is not charged.
//!
//! The facilitator here is in-process and counts settlements, so "not
//! charged" is asserted rather than claimed. Every refusal below is checked;
//! the run exits non-zero if one is not what this file says.

use aethel_auth::Holder;
use ex05_x402_seller_identity::demo::*;

fn expect(label: &str, got: (u16, String), status: u16, body: &str) {
    assert_eq!(got.0, status, "{label}: {}", got.1);
    assert!(
        got.1.contains(body),
        "{label}: expected {body:?}, got {:?}",
        got.1
    );
    println!("  {status}  {label}");
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let parties = Parties::new();
    let seller = seller(&parties, false);
    let delegation = delegate(&parties, bounds(Some(PRICE)));

    println!("x402 seller, 0.01 USDC per call, identity checked inside the payment layer:");

    // 1. A crawler or a new client with no payment gets the price.
    expect(
        "no payment: the 402 with the price",
        seller.send(request(None, None, None, None)).await,
        402,
        "",
    );

    // 2. Paid, but says nothing about who it acts for.
    let pay = payment_header(1);
    expect(
        "paid, no identity: refused",
        seller.send(request(Some(&pay), None, None, None)).await,
        403,
        "missing Aethel-Login",
    );
    assert_eq!(seller.settles(), 0, "a refused agent must not be charged");

    // 3. Paid, with the owner's delegation and a proof for this request.
    let proof = proof_for(&parties.agent, &pay, 1);
    expect(
        "paid, delegated, proven: served",
        seller
            .send(request(Some(&pay), Some(&proof), Some(&delegation), None))
            .await,
        200,
        "served agent",
    );
    assert_eq!(seller.settles(), 1);

    // 4. The same proof, lifted onto a different payment.
    let other_pay = payment_header(2);
    expect(
        "proof moved onto another payment: refused",
        seller
            .send(request(
                Some(&other_pay),
                Some(&proof),
                Some(&delegation),
                None,
            ))
            .await,
        403,
        "not for this request",
    );

    // 5. A price above what the owner allowed per call.
    let tight = delegate(&parties, bounds(Some(PRICE - 1)));
    let pay = payment_header(3);
    expect(
        "over the per-call ceiling: refused",
        seller
            .send(request(
                Some(&pay),
                Some(&proof_for(&parties.agent, &pay, 3)),
                Some(&tight),
                None,
            ))
            .await,
        403,
        "outside delegated bounds",
    );

    // 6. Above the owner's approval threshold: refused without the owner's
    //    step-up, served with it.
    let mut b = bounds(Some(PRICE));
    b.approval_required_above = Some(PRICE - 1);
    let needs_ok = delegate(&parties, b);
    let pay = payment_header(4);
    expect(
        "above the approval threshold, no approval: refused",
        seller
            .send(request(
                Some(&pay),
                Some(&proof_for(&parties.agent, &pay, 4)),
                Some(&needs_ok),
                None,
            ))
            .await,
        403,
        "needs the owner's approval",
    );
    let pay = payment_header(5);
    let approval = approval_for(&parties.owner, &needs_ok, &pay, 105);
    expect(
        "above the approval threshold, owner approved: served",
        seller
            .send(request(
                Some(&pay),
                Some(&proof_for(&parties.agent, &pay, 5)),
                Some(&needs_ok),
                Some(&approval),
            ))
            .await,
        200,
        "served agent",
    );

    // 7. The owner revokes its own key at this seller. Every delegation it
    //    gave here ends, including the one that worked in step 3.
    let revocation = Holder::new(&parties.owner, AUD).revoke_self(NOW);
    expect(
        "owner's revocation accepted",
        seller.send(revocation_request(&revocation)).await,
        204,
        "",
    );
    let pay = payment_header(6);
    expect(
        "after the owner revoked: refused",
        seller
            .send(request(
                Some(&pay),
                Some(&proof_for(&parties.agent, &pay, 6)),
                Some(&delegation),
                None,
            ))
            .await,
        403,
        "key revoked",
    );

    // Served twice (steps 3 and 6); every refusal left the payment unsettled.
    assert_eq!(seller.settles(), 2, "only served requests settle");
    println!(
        "settled {} of the paid requests; every refused one was left unsettled",
        seller.settles()
    );
}
