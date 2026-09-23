//! Signing an x402 / EIP-3009 payment authorization with `aethel-vault`.
//!
//! Run: `cargo run -p ex04-x402-vault-micropayments`
//!
//! x402 revives HTTP 402 Payment Required: the server answers with a price,
//! the client retries carrying an `X-PAYMENT` header, and the payment settles
//! on-chain as a USDC `transferWithAuthorization` (EIP-3009). No account, no
//! invoice, no human.
//!
//! What `aethel-vault` does and does not do matters here:
//!
//! * It does NOT hold your secp256k1 key and it contains no ECDSA code. You
//!   implement `SettlementSigner` around whatever already holds the key -
//!   hardware wallet, MPC, HSM, browser extension. This example uses `k256`
//!   directly to keep it runnable.
//! * It DOES build the EIP-712 digest, enforce a spend policy before the
//!   signer is ever asked, and sign its own ML-DSA-65 record of what it
//!   authorized. That record is the post-quantum audit trail: it survives
//!   the day secp256k1 does not.
//!
//! Keep `aethel-core` on the version `aethel-vault` uses (0.7 for vault 0.3):
//! `Identity` crosses between the two crates, and two copies in one graph
//! fail with "expected `Identity`, found `Identity`".
//!
//! One rough edge, real as of 2026-09-23:
//!
//! * Neither `VaultError` nor `IdentityError` implements
//!   `std::error::Error`, so `?` into `Box<dyn Error>` does not compile.
//!   This example converts with `map_err`.

use aethel_core::signing::Identity;
use aethel_vault::{Chain, Rail, SettlementError, SettlementSigner, SpendPolicy, Wallet};
use k256::ecdsa::{RecoveryId, SigningKey};
use sha3::{Digest, Keccak256};

/// A real ECDSA signer over `k256`. In production this is your wallet, not
/// a key sitting in process memory.
struct LocalSigner {
    key: SigningKey,
    address: [u8; 20],
}

impl LocalSigner {
    fn random() -> Self {
        let key = SigningKey::random(&mut rand::rngs::OsRng);

        // Ethereum address: last 20 bytes of keccak256 over the
        // uncompressed public key, minus its 0x04 prefix byte.
        let point = key.verifying_key().to_encoded_point(false);
        let hash = Keccak256::digest(&point.as_bytes()[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);

        LocalSigner { key, address }
    }
}

impl SettlementSigner for LocalSigner {
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 65], SettlementError> {
        // The digest is already the EIP-712 hash — sign it as-is, with no
        // further hashing.
        let (signature, recovery_id): (k256::ecdsa::Signature, RecoveryId) = self
            .key
            .sign_prehash_recoverable(digest)
            .map_err(|_| SettlementError::SignerRejected)?;

        // r ‖ s ‖ v, with v in EIP-155 legacy form (27 / 28).
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&signature.to_bytes());
        out[64] = recovery_id.to_byte() + 27;
        Ok(out)
    }

    fn address(&self) -> [u8; 20] {
        self.address
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("aethel-vault — x402 / EIP-3009 authorization\n");

    // 1. The settlement key. The vault never sees it.
    let signer = LocalSigner::random();
    println!("wallet:      0x{}", hex(&signer.address));

    // 2. The vault's own post-quantum identity. This signs the spend
    //    intent — the record of what was authorized and why it was allowed.
    let mut entropy = [0u8; 32];
    getrandom(&mut entropy);
    // `IdentityError` does not implement `std::error::Error`, so `?` into
    // `Box<dyn Error>` will not compile. Convert explicitly.
    let identity = Identity::generate(&entropy).map_err(|e| format!("{e:?}"))?;

    // 3. The standing policy, enforced before the signer is ever called.
    //    USDC has 6 decimals, so these are micro-dollars.
    let policy = SpendPolicy {
        max_per_call: 50_000, // $0.05 per request
        daily_cap: 2_000_000, // $2.00 per day
        allow_rails: vec![Rail::Eip3009Base],
        hitl_above: 500_000, // ask a human above $0.50
        ttl_secs: 3_600,
        hitl_approver_pk: None,
    };
    let mut wallet = Wallet::new(signer, identity, policy);
    println!("policy:      $0.05/call, $2.00/day, HITL above $0.50\n");

    // 4. Authorize one gateway request: 1,000 µUSDC = $0.001.
    let recipient = [0x11u8; 20];
    let nonce = [0x22u8; 32];
    let now = 1_758_480_000u64;

    let auth = wallet
        .authorize_eip3009(recipient, 1_000, nonce, Chain::Base, now, None)
        .map_err(|e| format!("{e:?}"))?;

    println!(
        "authorized:  $0.001 USDC on Base (chain {})",
        Chain::Base.chain_id()
    );
    println!(
        "valid:       {} .. {}",
        auth.authorization.valid_after, auth.authorization.valid_before
    );
    println!("ML-DSA intent signed: the PQC record of this authorization");

    // 5. The policy is not advisory. A request over the per-call cap is
    //    refused before the ECDSA signer is reached at all.
    let over_cap =
        wallet.authorize_eip3009(recipient, 5_000_000, [0x33u8; 32], Chain::Base, now, None);
    assert!(over_cap.is_err(), "the policy let a $5.00 call through");
    println!("\n$5.00 call:  refused by policy, signer never invoked");

    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn getrandom(buf: &mut [u8]) {
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(buf);
}
