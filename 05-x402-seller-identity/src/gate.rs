//! The seller's gate: an axum middleware that checks who a paying agent acts for.
//!
//! It only uses aethel-auth's verifier API; nothing here signs or holds a
//! secret. A tower layer placed *inside* x402-axum's layer. By the time it runs, the
//! facilitator has verified the payment but nothing has settled. A 4xx from
//! here means x402-axum does not settle (x402-axum 2.0.2 `paygate.rs`, the
//! settle-after branch), so a refused agent is not charged.
//!
//! Headers (all JSON, aethel-auth's own serde shapes, base64url bytes):
//! - `Aethel-Login`: a `LoginProof` from the agent, bound to this request with
//!   `Holder::login_for_request`.
//! - `Aethel-Delegation`: a `Delegation` from the owner (principal) to the agent.
//! - `Aethel-Approval` (only above the delegation's approval threshold): a
//!   `StepUpProof` from the owner, made with `Holder::approve` for this request.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use aethel_auth::{
    authorise, check_approval, verify_login_for_request, verify_revocation, AuthError, Delegation,
    InMemoryNonceStore, LoginProof, Revocation, StepUpProof, VerifyParams,
};
use axum::body::{to_bytes, Body};
use axum::extract::{Json, Request, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};

/// Delegation id to (window start, amount spent in the window).
pub type RunningTotals = HashMap<[u8; 32], (u64, u128)>;

pub const LOGIN_HEADER: &str = "aethel-login";
pub const DELEGATION_HEADER: &str = "aethel-delegation";
pub const APPROVAL_HEADER: &str = "aethel-approval";

/// What the seller decides per route: the action tag a delegation must list,
/// and the price in token base units, which is always passed to `authorise`
/// as `Some(amount)` (see `check`).
#[derive(Clone)]
pub struct RoutePrice {
    pub action: Vec<u8>,
    pub amount: u128,
}

#[derive(Clone)]
pub struct Policy {
    /// This seller's audience string. Delegations and proofs are for it only.
    pub audience: Vec<u8>,
    /// "Payment-Signature" (x402 V2) or "X-PAYMENT" (V1).
    pub pay_header: &'static str,
    /// Owner (principal) keys this seller has enrolled. The seller's own list,
    /// passed to `authorise` as the principals it recognises.
    pub owners: Arc<Vec<Vec<u8>>>,
    /// Keys the seller holds a verified revocation for, passed to `authorise`.
    pub revoked: Arc<Mutex<HashSet<Vec<u8>>>>,
    /// Keys allowed to revoke someone else's key here (`RevokedBy::Authority`).
    pub authorities: Arc<Vec<Vec<u8>>>,
    /// Running total per `Delegation::id`. In memory, like the nonce store:
    /// a real seller keeps both somewhere that survives a restart.
    pub totals: Arc<Mutex<RunningTotals>>,
    pub nonces: Arc<InMemoryNonceStore>,
    pub max_proof_age_secs: u64,
    pub price: RoutePrice,
    pub now: fn() -> u64,
}

/// What the handler sees after the gate passes.
#[derive(Clone, Debug)]
pub struct Caller {
    pub owner: Vec<u8>,
    pub agent: Vec<u8>,
    pub delegation_id: [u8; 32],
}

pub async fn aethel_gate(State(p): State<Policy>, req: Request, next: Next) -> Response {
    // The request digest covers the body, so read it once and put it back.
    let (parts, body) = req.into_parts();
    let Ok(bytes) = to_bytes(body, 1 << 20).await else {
        return refuse(StatusCode::PAYLOAD_TOO_LARGE, "body too large");
    };
    // `check` borrows the parts, not the request: a body is not `Sync`.
    match check(&p, &parts, &bytes).await {
        Ok(caller) => {
            let mut req = Request::from_parts(parts, Body::from(bytes));
            req.extensions_mut().insert(caller);
            next.run(req).await
        }
        Err(Refusal(status, why)) => refuse(status, why),
    }
}

/// A refusal: the status and the one-line reason sent back to the agent.
pub struct Refusal(pub StatusCode, pub &'static str);

fn deny(why: &'static str) -> Refusal {
    Refusal(StatusCode::FORBIDDEN, why)
}

fn from_auth(e: AuthError) -> Refusal {
    // A store failure is not a verdict about the agent (aethel-auth `is_rejection`).
    if !e.is_rejection() {
        return Refusal(StatusCode::SERVICE_UNAVAILABLE, "could not check identity");
    }
    deny(match e {
        AuthError::AudienceMismatch => "wrong audience",
        AuthError::StaleOrFutureProof => "proof too old or from the future",
        AuthError::Expired => "expired",
        AuthError::BadSignature => "signature invalid",
        AuthError::NonceAlreadyUsed => "proof already used",
        AuthError::RequestMismatch => "proof is not for this request",
        AuthError::RequestDigestNotChecked => "proof binding not checked",
        AuthError::NotDelegated => "outside delegated bounds",
        AuthError::NotAuthorised => "owner not recognised here",
        AuthError::Revoked => "key revoked",
        _ => "malformed",
    })
}

fn refuse(status: StatusCode, why: &'static str) -> Response {
    (status, format!("aethel: {why}")).into_response()
}

/// aethel-auth README's recommended digest, plus the payment header as one
/// more `lp(..)` field (the README's rule for a relying party that relies on a
/// header). Binding to the single-use x402 payment means a proof lifted onto
/// another payment fails `RequestMismatch`.
pub fn request_digest(method: &str, path_and_query: &str, body: &[u8], payment: &[u8]) -> [u8; 32] {
    fn lp(h: &mut Sha256, x: &[u8]) {
        h.update((x.len() as u32).to_be_bytes());
        h.update(x);
    }
    let mut h = Sha256::new();
    lp(&mut h, method.to_ascii_uppercase().as_bytes());
    lp(&mut h, path_and_query.as_bytes());
    lp(&mut h, &Sha256::digest(body));
    lp(&mut h, payment);
    h.finalize().into()
}

/// Every check the gate makes, without the middleware plumbing.
pub async fn check(p: &Policy, req: &Parts, body: &[u8]) -> Result<Caller, Refusal> {
    let header = |n: &str| req.headers.get(n).and_then(|v| v.to_str().ok());
    let proof: LoginProof =
        serde_json::from_str(header(LOGIN_HEADER).ok_or(deny("missing Aethel-Login"))?)
            .map_err(|_| deny("bad Aethel-Login"))?;
    let delegation: Delegation =
        serde_json::from_str(header(DELEGATION_HEADER).ok_or(deny("missing Aethel-Delegation"))?)
            .map_err(|_| deny("bad Aethel-Delegation"))?;
    let now = (p.now)();

    // 1. The agent proves control of its key, for this request and this payment.
    let pay = req
        .headers
        .get(p.pay_header)
        .ok_or(deny("no payment header"))?;
    let path = req
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let digest = request_digest(req.method.as_str(), path, body, pay.as_bytes());
    let params = VerifyParams {
        expected_audience: &p.audience,
        now,
        max_age_secs: p.max_proof_age_secs,
    };
    let who = verify_login_for_request(&proof, params, &digest, p.nonces.as_ref())
        .await
        .map_err(from_auth)?;

    // 2. The owner's delegation covers this agent, action and amount. aethel-auth
    // checks the owner is one this seller enrolled and that neither key is
    // revoked here. A paid route always has an amount, so it is always Some.
    let obligations = {
        let revoked = p.revoked.lock().unwrap();
        authorise(
            &delegation,
            &p.audience,
            &p.owners,
            &*revoked,
            &who.public_key,
            &p.price.action,
            Some(p.price.amount),
            now,
        )
        .map_err(from_auth)?
    };

    // 3. What authorise leaves to the seller: the owner's approval, then the running total.
    if obligations.human_approval_required {
        let step_up: StepUpProof = serde_json::from_str(
            header(APPROVAL_HEADER).ok_or(deny("needs the owner's approval"))?,
        )
        .map_err(|_| deny("bad Aethel-Approval"))?;
        // Verifies the owner signed approval_digest(delegation, this request's digest).
        check_approval(&delegation, &step_up, params, &digest, p.nonces.as_ref())
            .await
            .map_err(|e| {
                if e.is_rejection() {
                    deny("owner approval invalid")
                } else {
                    from_auth(e)
                }
            })?;
    }
    let id = delegation.id();
    if let Some(ceiling) = obligations.cumulative_ceiling {
        let window = obligations.window_secs.unwrap_or(u64::MAX);
        let mut totals = p.totals.lock().unwrap();
        let (start, spent) = totals.entry(id).or_insert((now, 0));
        if now.saturating_sub(*start) >= window {
            *start = now;
            *spent = 0;
        }
        let next = spent.saturating_add(p.price.amount);
        if next > ceiling {
            return Err(deny("over the delegation's total"));
        }
        // Counted before settlement; a failed settle over-counts, which fails safe.
        *spent = next;
    }

    Ok(Caller {
        owner: delegation.principal_key,
        agent: who.public_key,
        delegation_id: id,
    })
}

/// A revocation sent to the seller. Verified, then remembered.
pub fn accept_revocation(p: &Policy, r: &Revocation) -> Result<(), AuthError> {
    verify_revocation(r, &p.audience, &p.authorities)?;
    p.revoked.lock().unwrap().insert(r.subject_key.clone());
    Ok(())
}

/// `POST /aethel/revocations`: a signed `Revocation` sent to the seller.
/// An owner revoking its own key ends every delegation it gave at this seller.
pub async fn post_revocation(State(p): State<Policy>, Json(r): Json<Revocation>) -> StatusCode {
    match accept_revocation(&p, &r) {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::FORBIDDEN,
    }
}
