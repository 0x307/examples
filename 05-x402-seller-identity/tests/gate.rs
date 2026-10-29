//! Every case through the real x402-axum layer. Each refusal also asserts the
//! settlement count, so "a refused agent is not charged" is a check that can fail.

use std::collections::HashSet;

use aethel_auth::{authorise, revoke_as_authority, AuthError, Delegation, Holder};
use aethel_core::signing::Identity;
use ex05_x402_seller_identity::demo::*;

fn key(seed: u8) -> Identity {
    Identity::generate(&[seed; 32]).expect("32 bytes of entropy")
}

/// A paid request from the agent, under `d`, with a fresh payment and proof.
async fn paid(s: &Seller, p: &Parties, d: &Delegation, n: u8) -> (u16, String) {
    let pay = payment_header(n.into());
    s.send(request(
        Some(&pay),
        Some(&proof_for(&p.agent, &pay, n)),
        Some(d),
        None,
    ))
    .await
}

fn refused(got: (u16, String), why: &str) {
    assert_eq!(
        (got.0, got.1.as_str()),
        (403, format!("aethel: {why}").as_str())
    );
}

#[tokio::test]
async fn unpaid_probe_gets_a_clean_402() {
    let p = Parties::new();
    let s = seller(&p, false);
    assert_eq!(s.send(request(None, None, None, None)).await.0, 402);
    assert_eq!(s.settles(), 0);
}

#[tokio::test]
async fn paid_but_no_identity_is_refused_and_not_charged() {
    let p = Parties::new();
    let s = seller(&p, false);
    refused(
        s.send(request(Some(&payment_header(1)), None, None, None))
            .await,
        "missing Aethel-Login",
    );
    assert_eq!(s.settles(), 0);
}

#[tokio::test]
async fn owner_signs_agent_signs_seller_serves_and_settles() {
    let p = Parties::new();
    let s = seller(&p, false);
    let (status, body) = paid(&s, &p, &delegate(&p, bounds(Some(PRICE))), 1).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.starts_with("served agent "));
    assert_eq!(s.settles(), 1);
}

// ---- revocation ----

#[tokio::test]
async fn agent_revoked_by_an_authority_is_refused() {
    let p = Parties::new();
    let s = seller(&p, false);
    let r = revoke_as_authority(&p.authority, p.agent.public_key(), AUD, NOW);
    assert_eq!(s.send(revocation_request(&r)).await.0, 204);
    refused(
        paid(&s, &p, &delegate(&p, bounds(Some(PRICE))), 1).await,
        "key revoked",
    );
    assert_eq!(s.settles(), 0);
}

#[tokio::test]
async fn owner_revoking_its_own_key_ends_the_delegation() {
    let p = Parties::new();
    let s = seller(&p, false);
    let d = delegate(&p, bounds(Some(PRICE)));
    assert_eq!(paid(&s, &p, &d, 1).await.0, 200);
    let r = Holder::new(&p.owner, AUD).revoke_self(NOW);
    assert_eq!(s.send(revocation_request(&r)).await.0, 204);
    refused(paid(&s, &p, &d, 2).await, "key revoked");
    assert_eq!(s.settles(), 1);
}

#[tokio::test]
async fn a_revocation_from_a_stranger_is_not_accepted() {
    let p = Parties::new();
    let s = seller(&p, false);
    let r = revoke_as_authority(&key(9), p.agent.public_key(), AUD, NOW);
    assert_eq!(s.send(revocation_request(&r)).await.0, 403);
    assert_eq!(
        paid(&s, &p, &delegate(&p, bounds(Some(PRICE))), 1).await.0,
        200
    );
}

// ---- the owner's bounds ----

#[tokio::test]
async fn price_over_the_per_call_ceiling_is_refused() {
    let p = Parties::new();
    let s = seller(&p, false);
    refused(
        paid(&s, &p, &delegate(&p, bounds(Some(PRICE - 1))), 1).await,
        "outside delegated bounds",
    );
    assert_eq!(s.settles(), 0);
}

#[tokio::test]
async fn no_per_call_ceiling_means_refused_not_unlimited() {
    let p = Parties::new();
    let s = seller(&p, false);
    refused(
        paid(&s, &p, &delegate(&p, bounds(None)), 1).await,
        "outside delegated bounds",
    );
    assert_eq!(s.settles(), 0);
}

#[tokio::test]
async fn running_total_stops_the_fourth_call() {
    let p = Parties::new();
    let s = seller(&p, false);
    let d = delegate(&p, bounds(Some(PRICE))); // max_total = 3 * PRICE
    for n in 1..=3 {
        assert_eq!(paid(&s, &p, &d, n).await.0, 200);
    }
    refused(paid(&s, &p, &d, 4).await, "over the delegation's total");
    assert_eq!(s.settles(), 3);
}

// ---- the owner's approval above the threshold ----

fn needs_approval(p: &Parties, not_before: u64) -> Delegation {
    let mut b = bounds(Some(PRICE));
    b.approval_required_above = Some(PRICE - 1);
    Holder::new(&p.owner, AUD).delegate_to(p.agent.public_key(), b, not_before, NOW + 3600)
}

#[tokio::test]
async fn above_the_threshold_without_approval_is_held() {
    let p = Parties::new();
    let s = seller(&p, false);
    refused(
        paid(&s, &p, &needs_approval(&p, NOW - 60), 1).await,
        "needs the owner's approval",
    );
    assert_eq!(s.settles(), 0);
}

#[tokio::test]
async fn owner_approval_lets_the_request_through() {
    let p = Parties::new();
    let s = seller(&p, false);
    let d = needs_approval(&p, NOW - 60);
    let pay = payment_header(1);
    let a = approval_for(&p.owner, &d, &pay, 100);
    let (status, body) = s
        .send(request(
            Some(&pay),
            Some(&proof_for(&p.agent, &pay, 1)),
            Some(&d),
            Some(&a),
        ))
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(s.settles(), 1);
}

#[tokio::test]
async fn agent_approving_itself_is_refused() {
    let p = Parties::new();
    let s = seller(&p, false);
    let d = needs_approval(&p, NOW - 60);
    let pay = payment_header(1);
    let a = approval_for(&p.agent, &d, &pay, 100);
    refused(
        s.send(request(
            Some(&pay),
            Some(&proof_for(&p.agent, &pay, 1)),
            Some(&d),
            Some(&a),
        ))
        .await,
        "owner approval invalid",
    );
    assert_eq!(s.settles(), 0);
}

#[tokio::test]
async fn approval_for_another_payment_is_refused() {
    let p = Parties::new();
    let s = seller(&p, false);
    let d = needs_approval(&p, NOW - 60);
    let pay = payment_header(1);
    let a = approval_for(&p.owner, &d, &payment_header(2), 100);
    refused(
        s.send(request(
            Some(&pay),
            Some(&proof_for(&p.agent, &pay, 1)),
            Some(&d),
            Some(&a),
        ))
        .await,
        "owner approval invalid",
    );
    assert_eq!(s.settles(), 0);
}

#[tokio::test]
async fn approval_under_another_delegation_is_refused() {
    let p = Parties::new();
    let s = seller(&p, false);
    let d = needs_approval(&p, NOW - 60);
    // Same owner and terms, one second apart: a different delegation id.
    let other = needs_approval(&p, NOW - 61);
    let pay = payment_header(1);
    let a = approval_for(&p.owner, &other, &pay, 100);
    refused(
        s.send(request(
            Some(&pay),
            Some(&proof_for(&p.agent, &pay, 1)),
            Some(&d),
            Some(&a),
        ))
        .await,
        "owner approval invalid",
    );
    assert_eq!(s.settles(), 0);
}

// ---- the proof and the delegation themselves ----

#[tokio::test]
async fn proof_moved_onto_another_payment_is_refused() {
    let p = Parties::new();
    let s = seller(&p, false);
    let proof = proof_for(&p.agent, &payment_header(1), 1);
    let d = delegate(&p, bounds(Some(PRICE)));
    refused(
        s.send(request(
            Some(&payment_header(2)),
            Some(&proof),
            Some(&d),
            None,
        ))
        .await,
        "proof is not for this request",
    );
    assert_eq!(s.settles(), 0);
}

#[tokio::test]
async fn replayed_proof_is_refused() {
    let p = Parties::new();
    let s = seller(&p, false);
    let pay = payment_header(1);
    let proof = proof_for(&p.agent, &pay, 1);
    let d = delegate(&p, bounds(Some(PRICE)));
    assert_eq!(
        s.send(request(Some(&pay), Some(&proof), Some(&d), None))
            .await
            .0,
        200
    );
    refused(
        s.send(request(Some(&pay), Some(&proof), Some(&d), None))
            .await,
        "proof already used",
    );
    assert_eq!(s.settles(), 1);
}

#[tokio::test]
async fn delegation_proven_by_another_key_is_refused() {
    let p = Parties::new();
    let s = seller(&p, false);
    let pay = payment_header(1);
    let d = delegate(&p, bounds(Some(PRICE)));
    refused(
        s.send(request(
            Some(&pay),
            Some(&proof_for(&key(8), &pay, 1)),
            Some(&d),
            None,
        ))
        .await,
        "outside delegated bounds",
    );
    assert_eq!(s.settles(), 0);
}

#[tokio::test]
async fn owner_not_enrolled_here_is_refused() {
    let p = Parties::new();
    let s = seller(&p, false);
    let d = Holder::new(&key(7), AUD).delegate_to(
        p.agent.public_key(),
        bounds(Some(PRICE)),
        NOW - 60,
        NOW + 3600,
    );
    refused(paid(&s, &p, &d, 1).await, "owner not recognised here");
    assert_eq!(s.settles(), 0);
}

#[tokio::test]
async fn expired_delegation_is_refused() {
    let p = Parties::new();
    let s = seller(&p, false);
    let d = Holder::new(&p.owner, AUD).delegate_to(
        p.agent.public_key(),
        bounds(Some(PRICE)),
        NOW - 7200,
        NOW - 1,
    );
    refused(paid(&s, &p, &d, 1).await, "expired");
    assert_eq!(s.settles(), 0);
}

#[tokio::test]
async fn delegation_for_another_seller_is_refused() {
    let p = Parties::new();
    let s = seller(&p, false);
    let d = Holder::new(&p.owner, &b"https://other.example"[..]).delegate_to(
        p.agent.public_key(),
        bounds(Some(PRICE)),
        NOW - 60,
        NOW + 3600,
    );
    refused(paid(&s, &p, &d, 1).await, "wrong audience");
    assert_eq!(s.settles(), 0);
}

#[tokio::test]
async fn delegation_edited_after_signing_is_refused() {
    let p = Parties::new();
    let s = seller(&p, false);
    let mut d = delegate(&p, bounds(Some(PRICE)));
    d.bounds.max_total = Some(u128::MAX); // the agent widens its own budget
    refused(paid(&s, &p, &d, 1).await, "signature invalid");
    assert_eq!(s.settles(), 0);
}

/// The wrong configuration for this gate: settle first, check identity inside.
/// The refusal still happens, but after the charge. Asserted so the README's
/// warning stays true.
#[tokio::test]
async fn settle_before_execution_charges_a_refused_agent() {
    let p = Parties::new();
    let s = seller(&p, true);
    assert_eq!(
        s.send(request(Some(&payment_header(1)), None, None, None))
            .await
            .0,
        403
    );
    assert_eq!(s.settles(), 1);
}

// ---- what aethel-auth 0.2 refuses by itself ----
// The gate passes these inputs straight through; these tests show the crate,
// not the gate, is what refuses them.

#[test]
fn authorise_refuses_no_amount_under_a_bounded_delegation() {
    let p = Parties::new();
    let d = delegate(&p, bounds(Some(PRICE)));
    let owners = vec![p.owner.public_key()];
    let none: &[Vec<u8>] = &[];
    let agent = p.agent.public_key();
    assert_eq!(
        authorise(&d, AUD, &owners, none, &agent, ACTION, None, NOW).unwrap_err(),
        AuthError::NotDelegated
    );
    // Control: the same call with the price passes.
    assert!(authorise(&d, AUD, &owners, none, &agent, ACTION, Some(PRICE), NOW).is_ok());
}

#[test]
fn authorise_refuses_a_revoked_owner_or_agent() {
    let p = Parties::new();
    let d = delegate(&p, bounds(Some(PRICE)));
    let owners = vec![p.owner.public_key()];
    let agent = p.agent.public_key();
    for revoked_key in [p.agent.public_key(), p.owner.public_key()] {
        let revoked = HashSet::from([revoked_key]);
        assert_eq!(
            authorise(&d, AUD, &owners, &revoked, &agent, ACTION, Some(PRICE), NOW).unwrap_err(),
            AuthError::Revoked
        );
    }
    // Control: an unrelated revoked key changes nothing.
    let revoked = HashSet::from([key(9).public_key()]);
    assert!(authorise(&d, AUD, &owners, &revoked, &agent, ACTION, Some(PRICE), NOW).is_ok());
}

#[test]
fn authorise_refuses_an_owner_the_seller_does_not_recognise() {
    let p = Parties::new();
    let d = delegate(&p, bounds(Some(PRICE)));
    let none: &[Vec<u8>] = &[];
    let agent = p.agent.public_key();
    let others = vec![p.authority.public_key()];
    assert_eq!(
        authorise(&d, AUD, &others, none, &agent, ACTION, Some(PRICE), NOW).unwrap_err(),
        AuthError::NotAuthorised
    );
}
