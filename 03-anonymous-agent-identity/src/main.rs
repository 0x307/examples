//! Anonymous agent identity with `aethel-sdk` — no static DID, no reusable
//! public key.
//!
//! Run: `cargo run -p ex03-anonymous-agent-identity`
//!
//! A W3C DID is a stable, public identifier. Every service an agent touches
//! sees the same string, so any two of them can collude to correlate it.
//! An Aethel identity instead *projects* into each context: the identifier a
//! verifier sees is bound to that context and to fresh randomness, and
//! reveals nothing about the master secret or about the agent's other
//! contexts.

use aethel_sdk::{verify, Identity};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("aethel-sdk — post-quantum anonymous identity\n");

    // 1. Generate. The signing key is derived inside the embedded
    //    component and never enters this process.
    let mut identity = Identity::generate()?;

    // 2. Sign and verify, ML-DSA-65 underneath.
    let message = b"agent-42 accepts the gateway terms at 2026-09-21T18:00Z";
    let signature = identity.sign(message)?;
    assert!(verify(identity.public_key(), message, &signature)?);
    assert!(!verify(
        identity.public_key(),
        b"something else",
        &signature
    )?);
    println!("sign / verify:     ok (tampered message rejected)");

    // 3. The interoperable public form, when you do want one: base58btc
    //    Multikey. Note that publishing this is a choice — it is exactly
    //    the correlatable identifier that projections exist to avoid.
    let multikey = identity.public_key_multibase();
    println!("multikey:          {}...", &multikey[..20]);

    // 4. Projection. Two projections at the SAME context are independent:
    //    fresh randomness each time, so a verifier cannot link them, and
    //    neither exposes the master secret.
    let checkout_a = identity.project_at(b"checkout-session")?;
    let checkout_b = identity.project_at(b"checkout-session")?;
    assert_ne!(checkout_a.salt(), checkout_b.salt());
    assert_ne!(checkout_a.to_bytes(), checkout_b.to_bytes());
    println!("same context:      two projections, unlinkable");

    // 5. Different contexts are likewise independent. The gateway and the
    //    data vendor cannot compare notes and conclude they served the
    //    same agent.
    let vendor = identity.project_at(b"data-vendor-api")?;
    assert_ne!(checkout_a.to_bytes(), vendor.to_bytes());
    println!("cross context:     no shared identifier");
    println!(
        "projection carries {} public coefficients, no master secret",
        checkout_a.public_b().len()
    );

    // 6. Persistence. `key` must be high-entropy key material — NOT a
    //    password. Deriving one from a passphrase is the caller's job and
    //    wants a real KDF (Argon2id), not a hash.
    let sealing_key = b"a sealing key of thirty-two byte";
    let sealed = identity.export_sealed(sealing_key)?;
    let reopened = Identity::open_sealed(&sealed, sealing_key)?;
    assert_eq!(reopened.public_key_multibase(), multikey);
    println!("seal / reopen:     ok ({} bytes at rest)", sealed.len());

    Ok(())
}
