//! Post-quantum key encapsulation with `pqc-kem` (FIPS 203, ML-KEM-768).
//!
//! Run: `cargo run -p ex02-pqc-key-exchange`
//!
//! A KEM is not Diffie-Hellman. Nobody exchanges public values and derives a
//! shared secret from both halves. The recipient publishes a public key; the
//! sender *encapsulates* — generating a fresh shared secret and a ciphertext
//! that only the recipient's secret key can open. One round trip, no
//! negotiation.

use pqc_kem::fips203::{HybridKemKeypair, MlKem768Keypair};
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("pqc-kem — FIPS 203 ML-KEM-768\n");

    // ── Pure post-quantum: ML-KEM-768 ────────────────────────────────────
    let recipient = MlKem768Keypair::generate(&mut OsRng)?;
    let public_key = recipient.public_key();
    println!("public key:  {:>5} bytes", public_key.bytes.len());

    // Sender side: needs only the recipient's public key.
    let (ciphertext, sender_secret) = MlKem768Keypair::encapsulate(&mut OsRng, &public_key)?;
    println!("ciphertext:  {:>5} bytes", ciphertext.bytes.len());

    // Recipient side: recovers the identical secret.
    let recipient_secret = recipient.decapsulate(&ciphertext)?;
    assert_eq!(sender_secret.bytes, recipient_secret.bytes);
    println!(
        "shared secret: {:>3} bytes, both sides agree",
        sender_secret.bytes.len()
    );

    // Encapsulating again produces a different secret and a different
    // ciphertext. The shared secret is per-encapsulation, not per-keypair —
    // this is what makes it safe to publish one KEM public key forever.
    let (ct2, secret2) = MlKem768Keypair::encapsulate(&mut OsRng, &public_key)?;
    assert_ne!(ciphertext.bytes, ct2.bytes);
    assert_ne!(sender_secret.bytes, secret2.bytes);
    println!("re-encapsulation: fresh secret, as expected");

    // ── Hybrid: X25519 + ML-KEM-768 ──────────────────────────────────────
    //
    // The migration-safe choice. The session key is derived from BOTH the
    // classical and the post-quantum secret via HKDF, so it stays secure
    // unless both are broken. Use this in production until PQC-only is
    // uncontroversial; the cost is 32 extra bytes and one X25519 operation.
    println!("\nhybrid X25519 + ML-KEM-768");
    let hybrid = HybridKemKeypair::generate(&mut OsRng)?;
    let hybrid_pk = hybrid.public_key();

    let (hybrid_ct, hybrid_sender) = HybridKemKeypair::encapsulate_to(&mut OsRng, &hybrid_pk)?;
    let hybrid_recipient = hybrid.decapsulate(&hybrid_ct)?;

    assert_eq!(hybrid_sender.bytes, hybrid_recipient.bytes);
    println!(
        "shared secret: {:>3} bytes, HKDF-SHA256 over both halves",
        hybrid_sender.bytes.len()
    );

    Ok(())
}
