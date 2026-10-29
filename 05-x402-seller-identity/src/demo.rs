//! Everything around the gate that a real deployment replaces: an in-process
//! facilitator, a fixed clock, and the owner and agent, who sign with
//! aethel-auth's `Holder` (the `holder` feature). The seller code in
//! `gate.rs` never calls into this module.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use aethel_auth::{Bounds, Delegation, Holder, InMemoryNonceStore, LoginProof, StepUpProof};
use aethel_core::signing::Identity;
use axum::body::Body;
use axum::http::{Request, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde_json::json;
use tower::ServiceExt;
use x402_axum::X402Middleware;
use x402_types::chain::ChainId;
use x402_types::facilitator::Facilitator;
use x402_types::proto::{self, v1, v2, SupportedResponse};
use x402_types::util::Base64Bytes;

use crate::gate::*;

/// The seller's audience. Every delegation and proof names it.
pub const AUD: &[u8] = b"https://seller.example/premium";
/// A fixed clock, so every run is the same.
pub const NOW: u64 = 1_800_000_000;
/// 0.01 USDC, in base units (6 decimals).
pub const PRICE: u128 = 10_000;
/// The action tag a delegation must list for this route.
pub const ACTION: &[u8] = b"GET /premium";
/// x402 V2 payment header.
pub const PAY: &str = "Payment-Signature";

fn now() -> u64 {
    NOW
}

/// A facilitator that says every payment is valid and counts what it is
/// asked to do. Counting settlements is what lets the tests prove that a
/// refused agent is not charged. A real seller points `X402Middleware` at a
/// facilitator URL instead.
#[derive(Clone, Default)]
pub struct FakeFacilitator {
    pub settles: Arc<AtomicUsize>,
}

impl Facilitator for FakeFacilitator {
    type Error = std::convert::Infallible;

    async fn verify(&self, _: &proto::VerifyRequest) -> Result<proto::VerifyResponse, Self::Error> {
        Ok(v1::VerifyResponse::valid("0x00000000000000000000000000000000000000aa".into()).into())
    }

    async fn settle(&self, _: &proto::SettleRequest) -> Result<proto::SettleResponse, Self::Error> {
        self.settles.fetch_add(1, Ordering::SeqCst);
        Ok(proto::SettleResponse(json!({
            "success": true, "transaction": "0xfeed", "network": "eip155:84532",
            "payer": "0x00000000000000000000000000000000000000aa"
        })))
    }

    async fn supported(&self) -> Result<SupportedResponse, Self::Error> {
        Ok(SupportedResponse {
            kinds: vec![],
            extensions: vec![],
            signers: HashMap::new(),
        })
    }
}

/// What the seller asks for: 0.01 USDC on Base Sepolia.
pub fn requirements() -> v2::PaymentRequirements {
    v2::PaymentRequirements {
        scheme: "exact".into(),
        network: ChainId::new("eip155", "84532"),
        amount: PRICE.to_string(),
        pay_to: "0x00000000000000000000000000000000000000bb".into(),
        max_timeout_seconds: 60,
        asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e".into(),
        extra: None,
    }
}

/// A V2 payment header. `n` stands in for the single-use EIP-3009 nonce a
/// real payer signs (example 04 shows that part).
pub fn payment_header(n: u32) -> String {
    let payload = json!({
        "x402Version": 2,
        "accepted": requirements(),
        "payload": { "fakeAuthorizationNonce": n },
    });
    let encoded = Base64Bytes::encode(serde_json::to_vec(&payload).expect("json"));
    String::from_utf8(encoded.as_ref().to_vec()).expect("base64 is ascii")
}

/// The owner, its agent, and a key the seller lets revoke other keys.
pub struct Parties {
    pub owner: Identity,
    pub agent: Identity,
    pub authority: Identity,
}

impl Parties {
    /// Fixed seeds, so key fingerprints are the same on every run. Use real
    /// entropy for real keys.
    pub fn new() -> Self {
        Parties {
            owner: Identity::generate(&[1u8; 32]).expect("32 bytes of entropy"),
            agent: Identity::generate(&[2u8; 32]).expect("32 bytes of entropy"),
            authority: Identity::generate(&[3u8; 32]).expect("32 bytes of entropy"),
        }
    }
}

impl Default for Parties {
    fn default() -> Self {
        Self::new()
    }
}

/// The seller's app, plus what the tests need to look at.
pub struct Seller {
    pub app: Router,
    pub policy: Policy,
    pub facilitator: FakeFacilitator,
}

impl Seller {
    pub fn settles(&self) -> usize {
        self.facilitator.settles.load(Ordering::SeqCst)
    }

    pub async fn send(&self, req: Request<Body>) -> (u16, String) {
        let res: Response<Body> = self.app.clone().oneshot(req).await.expect("infallible");
        let status = res.status().as_u16();
        let body = axum::body::to_bytes(res.into_body(), 1 << 16)
            .await
            .expect("body");
        (status, String::from_utf8_lossy(&body).into_owned())
    }
}

async fn premium(Extension(caller): Extension<Caller>) -> String {
    format!(
        "served agent {}",
        aethel_auth::key_fingerprint(&caller.agent)
    )
}

/// The seller: one paid route with the gate inside the payment layer, and an
/// unpaid route that accepts signed revocations.
pub fn seller(parties: &Parties, settle_before_execution: bool) -> Seller {
    let policy = Policy {
        audience: AUD.to_vec(),
        pay_header: PAY,
        owners: Arc::new(vec![parties.owner.public_key()]),
        revoked: Arc::new(Mutex::new(HashSet::new())),
        authorities: Arc::new(vec![parties.authority.public_key()]),
        totals: Arc::new(Mutex::new(HashMap::new())),
        nonces: Arc::new(InMemoryNonceStore::new()),
        max_proof_age_secs: 120,
        price: RoutePrice {
            action: ACTION.to_vec(),
            amount: PRICE,
        },
        now,
    };
    let facilitator = FakeFacilitator::default();
    let mut x402 = X402Middleware::from_facilitator(facilitator.clone());
    if settle_before_execution {
        // The wrong order for this gate: see the README.
        x402 = x402.settle_before_execution();
    }
    let price_tag = v2::PriceTag {
        requirements: requirements(),
        enricher: None,
    };
    let app = Router::new()
        .route(
            "/premium",
            get(premium)
                // Added first, so it is the inner layer: it runs after the
                // facilitator has verified the payment, before anything settles.
                .layer(axum::middleware::from_fn_with_state(
                    policy.clone(),
                    aethel_gate,
                ))
                // Added last, so it is the outer layer: an unpaid probe still
                // gets a clean 402 with the price.
                .layer(x402.with_price_tag(price_tag)),
        )
        .route(
            "/aethel/revocations",
            post(post_revocation).with_state(policy.clone()),
        );
    Seller {
        app,
        policy,
        facilitator,
    }
}

/// Bounds for the walkthrough: this route only, at most the price per call,
/// three calls a day, and the owner's approval above ten times the price.
pub fn bounds(max_per_invocation: Option<u128>) -> Bounds {
    Bounds {
        actions: vec![ACTION.to_vec()],
        max_per_invocation,
        max_total: Some(PRICE * 3),
        window_secs: Some(86_400),
        approval_required_above: Some(PRICE * 10),
    }
}

/// The owner delegates to its agent, at this seller, for an hour.
pub fn delegate(parties: &Parties, bounds: Bounds) -> Delegation {
    Holder::new(&parties.owner, AUD).delegate_to(
        parties.agent.public_key(),
        bounds,
        NOW - 60,
        NOW + 3600,
    )
}

/// The agent proves itself for exactly this request and this payment.
pub fn proof_for(agent: &Identity, pay: &str, nonce: u8) -> LoginProof {
    let digest = request_digest("GET", "/premium", b"", pay.as_bytes());
    Holder::new(agent, AUD).login_for_request([nonce; 32], NOW - 1, 60, digest)
}

/// The owner approves one request under one delegation.
pub fn approval_for(
    owner: &Identity,
    delegation: &Delegation,
    pay: &str,
    nonce: u8,
) -> StepUpProof {
    let digest = request_digest("GET", "/premium", b"", pay.as_bytes());
    Holder::new(owner, AUD).approve(delegation, &digest, [nonce; 32], NOW - 1, 60)
}

/// A request to the paid route. Every part is optional so tests can leave one out.
pub fn request(
    pay: Option<&str>,
    proof: Option<&LoginProof>,
    delegation: Option<&Delegation>,
    approval: Option<&StepUpProof>,
) -> Request<Body> {
    let mut b = Request::get("/premium");
    if let Some(pay) = pay {
        b = b.header(PAY, pay);
    }
    if let Some(proof) = proof {
        b = b.header(LOGIN_HEADER, serde_json::to_string(proof).expect("json"));
    }
    if let Some(d) = delegation {
        b = b.header(DELEGATION_HEADER, serde_json::to_string(d).expect("json"));
    }
    if let Some(a) = approval {
        b = b.header(APPROVAL_HEADER, serde_json::to_string(a).expect("json"));
    }
    b.body(Body::empty()).expect("request")
}

/// A revocation sent to the seller's revocation route.
pub fn revocation_request(r: &aethel_auth::Revocation) -> Request<Body> {
    Request::post("/aethel/revocations")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(r).expect("json")))
        .expect("request")
}
