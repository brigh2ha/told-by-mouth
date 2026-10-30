//! Told by Mouth server.
//!
//! It does three small things and stores no reviews:
//!
//! - issues real-name certificates after an identity check and a device
//!   attestation (and renews them),
//! - stamps visits, seeing only the visit_id,
//! - publishes the signed revocation list.
//!
//! All signing uses the same encodings as the phones (`tbm_core`).

pub mod config;
pub mod db;
pub mod keys;
pub mod providers;

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::json;

use tbm_core::cbor::Cbor;
use tbm_core::crypto::{hex, sha256, PublicKey, Signature, Signer, SoftwareSigner};
use tbm_core::limits::{CLOCK_DRIFT, REAL_NAME_MAX, RENEW_WINDOW};
use tbm_core::model::{check_len, Certificate, RevocationList, Stamp, UserId};
use tbm_core::trust::Trust;

use crate::db::{person_hash, Db};
use crate::providers::{Attestation, IdentityProvider, ProviderError};

/// Seconds since 1970; replaceable in tests.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

pub fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock before 1970")
            .as_secs()
    })
}

pub struct AppState {
    pub db: Mutex<Db>,
    pub key: SoftwareSigner,
    pub key_id: u8,
    pub identity: Box<dyn IdentityProvider>,
    pub attestation: Box<dyn Attestation>,
    /// `None` turns the admin endpoints off.
    pub admin_token: Option<String>,
    pub clock: Clock,
}

impl AppState {
    fn trust(&self) -> Trust {
        Trust::new([(self.key_id, self.key.public_key())])
    }
}

pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/server-key", get(server_key))
        .route("/v1/certificates", post(issue_certificate))
        .route("/v1/certificates/renew", post(renew_certificate))
        .route("/v1/stamps", post(stamp))
        .route("/v1/revocations", get(revocations))
        .route("/v1/admin/revoke", post(admin_revoke))
        .with_state(state)
}

// ------------------------------------------------------------ errors

#[derive(Debug)]
pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

fn forbidden(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::FORBIDDEN, msg.into())
}

fn internal(msg: impl Into<String>) -> ApiError {
    let msg = msg.into();
    tracing::error!("{msg}");
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
}

fn provider_err(what: &str, e: ProviderError) -> ApiError {
    match e {
        ProviderError::Rejected(why) => forbidden(format!("{what} rejected: {why}")),
        ProviderError::NotConfigured => ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("{what} is not configured on this server"),
        ),
    }
}

type ApiResult<T> = Result<Json<T>, ApiError>;

fn b64(s: &str, what: &str) -> Result<Vec<u8>, ApiError> {
    B64.decode(s)
        .map_err(|_| bad(format!("{what} is not valid base64")))
}

// ------------------------------------------------------------ requests

#[derive(Deserialize)]
pub struct IdentityProof {
    pub provider: String,
    pub token: String,
}

#[derive(Deserialize)]
pub struct AttestationProof {
    pub platform: String,
    pub token: String,
}

#[derive(Deserialize)]
pub struct CertificateRequest {
    /// SEC1 P-256 public key from the secure chip, base64.
    pub public_key: String,
    pub identity: IdentityProof,
    pub attestation: AttestationProof,
}

#[derive(Deserialize)]
pub struct RenewRequest {
    /// The current certificate (CBOR, base64).
    pub certificate: String,
    /// When the phone signed this request.
    pub signed_at: u64,
    /// Device-key signature over `Certificate::renew_request_bytes`, base64.
    pub signature: String,
    pub attestation: AttestationProof,
}

#[derive(Deserialize)]
pub struct StampRequest {
    /// The visit id (32 bytes, base64). The server sees nothing else.
    pub visit_id: String,
    pub attestation: AttestationProof,
}

#[derive(Deserialize)]
pub struct RevokeRequest {
    /// Revoke a person: hex user id.
    pub user_id: Option<String>,
    /// Revoke one device key: base64 SEC1 key.
    pub device_key: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct CertificateResponse {
    /// CBOR, base64.
    pub certificate: String,
    pub user_id: String,
    pub expires_at: u64,
}

#[derive(Serialize, Deserialize)]
pub struct StampResponse {
    /// CBOR Stamp (stamp_at, server_key_id, stamp_sig), base64.
    pub stamp: String,
    pub stamp_at: u64,
}

#[derive(Serialize, Deserialize)]
pub struct RevocationsResponse {
    /// CBOR RevocationList, base64.
    pub revocations: String,
    pub issued_at: u64,
}

// ------------------------------------------------------------ handlers

async fn healthz() -> &'static str {
    "ok"
}

async fn server_key(State(s): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let key = s.key.public_key();
    Json(json!({
        "server_key_id": s.key_id,
        "public_key": B64.encode(key.0),
        "public_key_hex": hex(&key.0),
    }))
}

async fn issue_certificate(
    State(s): State<Arc<AppState>>,
    Json(req): Json<CertificateRequest>,
) -> ApiResult<CertificateResponse> {
    let key = PublicKey::from_sec1(&b64(&req.public_key, "public_key")?)
        .map_err(|_| bad("public_key is not a P-256 key"))?;
    s.attestation
        .verify(
            &req.attestation.platform,
            &req.attestation.token,
            &sha256(&key.0),
        )
        .map_err(|e| provider_err("attestation", e))?;
    let person = s
        .identity
        .verify(&req.identity.provider, &req.identity.token)
        .map_err(|e| provider_err("identity check", e))?;
    check_len("real name", &person.real_name, 1, REAL_NAME_MAX).map_err(|e| bad(e.to_string()))?;

    let now = (s.clock)();
    let db = s.db.lock().unwrap();
    let (user, revoked) = db
        .user_for_person(
            &person_hash(&req.identity.provider, &person.person_ref),
            now,
        )
        .map_err(internal)?;
    if revoked {
        return Err(forbidden("this person is revoked"));
    }
    if let Some(owner) = db.active_key_owner(&key).map_err(internal)? {
        if owner != user {
            return Err(forbidden("this key belongs to someone else"));
        }
    }
    let cert = Certificate::issue(&s.key, s.key_id, user, &person.real_name, key, now)
        .map_err(|e| internal(e.to_string()))?;
    // A new phone gets a new key; the old one stops being trusted from now.
    let replaced = db.revoke_other_keys(&user, &key, now).map_err(internal)?;
    db.record_certificate(&user, &key, cert.issued_at, cert.expires_at)
        .map_err(internal)?;
    tracing::info!(user = %hex(&user), replaced, "issued certificate");
    Ok(Json(CertificateResponse {
        certificate: B64.encode(cert.to_cbor()),
        user_id: hex(&user),
        expires_at: cert.expires_at,
    }))
}

async fn renew_certificate(
    State(s): State<Arc<AppState>>,
    Json(req): Json<RenewRequest>,
) -> ApiResult<CertificateResponse> {
    let cert = Certificate::from_cbor(&b64(&req.certificate, "certificate")?)
        .map_err(|_| bad("certificate is not valid"))?;
    s.trust()
        .verify_certificate(&cert)
        .map_err(|_| forbidden("certificate was not issued by this server"))?;
    let now = (s.clock)();
    if req.signed_at + CLOCK_DRIFT < now || req.signed_at > now + CLOCK_DRIFT {
        return Err(forbidden("request time is too far from server time"));
    }
    let sig: [u8; 64] = b64(&req.signature, "signature")?
        .try_into()
        .map_err(|_| bad("signature must be 64 bytes"))?;
    cert.device_key
        .verify(
            &cert.renew_request_bytes(req.signed_at),
            &Signature(sig),
            "renew",
        )
        .map_err(|_| forbidden("signature does not match the certificate's key"))?;
    if now + RENEW_WINDOW < cert.expires_at {
        return Err(forbidden("renewal opens 30 days before expiry"));
    }
    s.attestation
        .verify(
            &req.attestation.platform,
            &req.attestation.token,
            &sha256(&cert.device_key.0),
        )
        .map_err(|e| provider_err("attestation", e))?;

    let db = s.db.lock().unwrap();
    if db.user_revoked(&cert.user_id).map_err(internal)? != Some(false) {
        return Err(forbidden("this person is revoked or unknown"));
    }
    if db.active_key_owner(&cert.device_key).map_err(internal)? != Some(cert.user_id) {
        return Err(forbidden("this key is revoked"));
    }
    let new = Certificate::issue(
        &s.key,
        s.key_id,
        cert.user_id,
        &cert.real_name,
        cert.device_key,
        now,
    )
    .map_err(|e| internal(e.to_string()))?;
    db.record_certificate(&new.user_id, &new.device_key, new.issued_at, new.expires_at)
        .map_err(internal)?;
    tracing::info!(user = %hex(&new.user_id), "renewed certificate");
    Ok(Json(CertificateResponse {
        certificate: B64.encode(new.to_cbor()),
        user_id: hex(&new.user_id),
        expires_at: new.expires_at,
    }))
}

async fn stamp(
    State(s): State<Arc<AppState>>,
    Json(req): Json<StampRequest>,
) -> ApiResult<StampResponse> {
    let visit_id: [u8; 32] = b64(&req.visit_id, "visit_id")?
        .try_into()
        .map_err(|_| bad("visit_id must be 32 bytes"))?;
    s.attestation
        .verify(&req.attestation.platform, &req.attestation.token, &visit_id)
        .map_err(|e| provider_err("attestation", e))?;
    let now = (s.clock)();
    let stamp =
        Stamp::issue(&s.key, s.key_id, &visit_id, now).map_err(|e| internal(e.to_string()))?;
    Ok(Json(StampResponse {
        stamp: B64.encode(stamp.to_cbor()),
        stamp_at: now,
    }))
}

async fn revocations(State(s): State<Arc<AppState>>) -> ApiResult<RevocationsResponse> {
    let (users, keys) = s.db.lock().unwrap().revocations().map_err(internal)?;
    let now = (s.clock)();
    let list = RevocationList::issue(&s.key, s.key_id, now, users, keys)
        .map_err(|e| internal(e.to_string()))?;
    Ok(Json(RevocationsResponse {
        revocations: B64.encode(list.to_cbor()),
        issued_at: now,
    }))
}

/// Compares without stopping at the first difference.
fn same_token(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn admin_revoke(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<RevokeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let Some(expected) = &s.admin_token else {
        return Err(ApiError(StatusCode::NOT_FOUND, "admin is disabled".into()));
    };
    let given = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if !same_token(given, expected) {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "bad admin token".into()));
    }
    let now = (s.clock)();
    let db = s.db.lock().unwrap();
    let changed = match (&req.user_id, &req.device_key) {
        (Some(u), None) => {
            let user: UserId = parse_hex(u)
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| bad("user_id must be 32 hex characters"))?;
            if db.user_revoked(&user).map_err(internal)?.is_none() {
                return Err(ApiError(StatusCode::NOT_FOUND, "unknown user".into()));
            }
            db.revoke_user(&user, now).map_err(internal)?
        }
        (None, Some(k)) => {
            let key = PublicKey::from_sec1(&b64(k, "device_key")?)
                .map_err(|_| bad("device_key is not a P-256 key"))?;
            db.revoke_key(&key, now).map_err(internal)?
        }
        _ => return Err(bad("give exactly one of user_id or device_key")),
    };
    tracing::warn!(user_id = ?req.user_id, device_key = ?req.device_key, changed, "revoked");
    Ok(Json(json!({ "revoked": changed, "at": now })))
}

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}
