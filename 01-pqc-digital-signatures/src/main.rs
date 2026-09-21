//! Post-quantum digital signatures with `pqc-sig` (FIPS 204, ML-DSA-65).
//!
//! Run: `cargo run -p ex01-pqc-digital-signatures`
//!
//! ML-DSA-65 is the drop-in replacement for Ed25519 when the threat model
//! includes a quantum adversary. The trade is size: a signature goes from
//! 64 bytes to 3,309, and a public key from 32 to 1,952. Nothing else about
//! how you use it changes.

use pqc_sig::fips204::MlDsa65Keypair;
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("pqc-sig {} — FIPS 204 ML-DSA-65\n", pqc_sig::VERSION);

    // 1. Key generation. Entropy comes from the OS.
    let keypair = MlDsa65Keypair::generate(&mut OsRng)?;
    let public_key = keypair.public_key();
    println!("public key:  {:>5} bytes", public_key.bytes.len());

    // 2. Plain sign / verify.
    let message = b"agent-42 requests 0.05 USDC from the gateway";
    let signature = keypair.sign(&mut OsRng, message)?;
    println!("signature:   {:>5} bytes", signature.bytes.len());

    MlDsa65Keypair::verify(&public_key, message, &signature)?;
    println!("verify:            ok");

    // A different message under the same signature must fail. An example
    // that only shows the happy path has not shown you anything.
    assert!(
        MlDsa65Keypair::verify(&public_key, b"agent-42 requests 500 USDC", &signature).is_err(),
        "a tampered message verified — that is a bug, not a demo"
    );
    println!("tamper:        rejected");

    // 3. Context-bound signing. The context string is bound into the
    //    signature, so a signature produced for one protocol cannot be
    //    replayed into another. Use this in preference to plain `sign`
    //    whenever the signature travels between systems.
    let ctx = b"0x307-example-v1";
    let bound = keypair.sign_ctx(&mut OsRng, ctx, message)?;
    MlDsa65Keypair::verify_ctx(&public_key, ctx, message, &bound)?;
    println!("ctx verify:        ok");

    assert!(
        MlDsa65Keypair::verify_ctx(&public_key, b"some-other-protocol", message, &bound).is_err(),
        "a signature verified under the wrong context — domain separation is broken"
    );
    println!("wrong ctx:     rejected");

    // 4. The interoperable encoding: W3C Multikey, base58btc over the
    //    registered multicodec code for ML-DSA-65. This is what goes in a
    //    DID document or a JWK-adjacent key field.
    let multibase = public_key.to_multibase()?;
    println!("\nmultikey:    {}...", &multibase[..24]);

    Ok(())
}
