//! Integration tests: the HTTP API, driven the way the phones will call it,
//! and checked with the same core code the phones run.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use tbm_core::cbor::Cbor;
use tbm_core::crypto::{sha256, Signer, SoftwareSigner};
use tbm_core::limits::DAY;
use tbm_core::model::{Certificate, Fix, RevocationList, Stamp};
use tbm_core::review::{verify_review, Draft};
use tbm_core::store::Store;
use tbm_core::testkit::gangnam;
use tbm_core::trust::Trust;
use tbm_core::Node;
use tbm_server::db::Db;
use tbm_server::providers::{DevAttestation, DevIdentity, NotConfigured};
use tbm_server::{app, AppState};

const T0: u64 = 1_790_000_000;
const ADMIN: &str = "0123456789abcdef0123456789abcdef";

struct Server {
    router: axum::Router,
    clock: Arc<AtomicU64>,
}

fn server() -> Server {
    let clock = Arc::new(AtomicU64::new(T0));
    let c = clock.clone();
    let state = AppState {
        db: Mutex::new(Db::open_in_memory().unwrap()),
        key: SoftwareSigner::generate(),
        key_id: 3,
        identity: Box::new(DevIdentity),
        attestation: Box::new(DevAttestation),
        admin_token: Some(ADMIN.into()),
        clock: Arc::new(move || c.load(Ordering::SeqCst)),
    };
    Server {
        router: app(Arc::new(state)),
        clock,
    }
}

impl Server {
    async fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        auth: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut req = Request::builder().method(method).uri(path);
        if let Some(a) = auth {
            req = req.header("authorization", format!("Bearer {a}"));
        }
        let req = match body {
            Some(b) => req
                .header("content-type", "application/json")
                .body(Body::from(b.to_string()))
                .unwrap(),
            None => req.body(Body::empty()).unwrap(),
        };
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let value = serde_json::from_slice(&bytes)
            .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into()));
        (status, value)
    }

    async fn trust(&self) -> Trust {
        let (_, v) = self.call("GET", "/v1/server-key", None, None).await;
        let key = tbm_core::crypto::PublicKey::from_sec1(
            &B64.decode(v["public_key"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        Trust::new([(v["server_key_id"].as_u64().unwrap() as u8, key)])
    }

    async fn certificate(&self, name: &str, key: &dyn Signer) -> (StatusCode, Value) {
        self.call(
            "POST",
            "/v1/certificates",
            Some(json!({
                "public_key": B64.encode(key.public_key().0),
                "identity": { "provider": "dev", "token": name },
                "attestation": { "platform": "dev", "token": "ok" },
            })),
            None,
        )
        .await
    }

    fn set_time(&self, t: u64) {
        self.clock.store(t, Ordering::SeqCst);
    }
}

fn cert_of(v: &Value) -> Certificate {
    Certificate::from_cbor(&B64.decode(v["certificate"].as_str().unwrap()).unwrap()).unwrap()
}

#[tokio::test]
async fn health_and_server_key() {
    let s = server();
    let (st, v) = s.call("GET", "/healthz", None, None).await;
    assert_eq!((st, v), (StatusCode::OK, Value::String("ok".into())));
    let (st, v) = s.call("GET", "/v1/server-key", None, None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["server_key_id"], 3);
    assert_eq!(v["public_key_hex"].as_str().unwrap().len(), 66);
}

#[tokio::test]
async fn issues_a_certificate_the_phones_accept() {
    let s = server();
    let trust = s.trust().await;
    let phone = SoftwareSigner::generate();
    let (st, v) = s.certificate("Kim Minji", &phone).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let cert = cert_of(&v);
    assert_eq!(cert.real_name, "Kim Minji");
    assert_eq!(cert.device_key, phone.public_key());
    assert_eq!(cert.server_key_id, 3);
    assert_eq!(cert.expires_at, T0 + 365 * DAY);
    trust.check_certificate_at(&cert, T0 + DAY).unwrap();
    assert_eq!(
        v["user_id"].as_str().unwrap(),
        tbm_core::crypto::hex(&cert.user_id)
    );
}

#[tokio::test]
async fn a_new_phone_keeps_the_user_id_and_revokes_the_old_key() {
    let s = server();
    let old_phone = SoftwareSigner::generate();
    let new_phone = SoftwareSigner::generate();
    let old = cert_of(&s.certificate("Kim Minji", &old_phone).await.1);
    s.set_time(T0 + 10 * DAY);
    let new = cert_of(&s.certificate("Kim Minji", &new_phone).await.1);
    assert_eq!(old.user_id, new.user_id);

    let (_, v) = s.call("GET", "/v1/revocations", None, None).await;
    let list = RevocationList::from_cbor(&B64.decode(v["revocations"].as_str().unwrap()).unwrap())
        .unwrap();
    let mut trust = s.trust().await;
    trust.update_revocations(list.clone()).unwrap();
    assert!(list.users.is_empty());
    assert_eq!(list.keys.len(), 1);
    assert_eq!(list.keys[0].key, old_phone.public_key());
    // Reviews written with the old phone before the switch stay valid.
    trust.check_certificate_at(&old, T0 + DAY).unwrap();
    assert!(trust.check_certificate_at(&old, T0 + 11 * DAY).is_err());
    trust.check_certificate_at(&new, T0 + 11 * DAY).unwrap();

    // The old key cannot be used for somebody else.
    let (st, _) = s.certificate("Lee Jiwoo", &new_phone).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn refuses_bad_requests() {
    let s = server();
    let phone = SoftwareSigner::generate();
    let (st, _) = s
        .call(
            "POST",
            "/v1/certificates",
            Some(json!({
                "public_key": B64.encode(phone.public_key().0),
                "identity": { "provider": "dev", "token": "Kim" },
                "attestation": { "platform": "dev", "token": "rooted" },
            })),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, _) = s
        .call(
            "POST",
            "/v1/certificates",
            Some(json!({
                "public_key": B64.encode([9u8; 33]),
                "identity": { "provider": "dev", "token": "Kim" },
                "attestation": { "platform": "dev", "token": "ok" },
            })),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, _) = s.certificate(&"가".repeat(51), &phone).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, _) = s.certificate("Kim", &phone).await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn without_dev_mode_nothing_is_issued() {
    let state = AppState {
        db: Mutex::new(Db::open_in_memory().unwrap()),
        key: SoftwareSigner::generate(),
        key_id: 1,
        identity: Box::new(NotConfigured),
        attestation: Box::new(NotConfigured),
        admin_token: None,
        clock: Arc::new(|| T0),
    };
    let s = Server {
        router: app(Arc::new(state)),
        clock: Arc::new(AtomicU64::new(T0)),
    };
    let phone = SoftwareSigner::generate();
    let (st, _) = s.certificate("Kim", &phone).await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    let (st, _) = s
        .call("POST", "/v1/stamps", Some(json!({ "visit_id": B64.encode([1u8; 32]), "attestation": { "platform": "dev", "token": "ok" } })), None)
        .await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    let (st, _) = s
        .call(
            "POST",
            "/v1/admin/revoke",
            Some(json!({ "user_id": "00" })),
            Some(ADMIN),
        )
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn renewal_window_and_signature() {
    let s = server();
    let phone = SoftwareSigner::generate();
    let cert = cert_of(&s.certificate("Kim Minji", &phone).await.1);
    let renew = |at: u64, signer: &SoftwareSigner| {
        let sig = signer.sign(&cert.renew_request_bytes(at)).unwrap();
        json!({
            "certificate": B64.encode(cert.to_cbor()),
            "signed_at": at,
            "signature": B64.encode(sig.0),
            "attestation": { "platform": "dev", "token": "ok" },
        })
    };

    // Too early.
    let t = T0 + 100 * DAY;
    s.set_time(t);
    let (st, _) = s
        .call(
            "POST",
            "/v1/certificates/renew",
            Some(renew(t, &phone)),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // In the last 30 days: fine, with a later expiry and the same identity.
    let t = cert.expires_at - 10 * DAY;
    s.set_time(t);
    let (st, _) = s
        .call(
            "POST",
            "/v1/certificates/renew",
            Some(renew(t, &SoftwareSigner::generate())),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "someone else's signature");
    let (st, _) = s
        .call(
            "POST",
            "/v1/certificates/renew",
            Some(renew(t - 3600, &phone)),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "stale request");
    let (st, v) = s
        .call(
            "POST",
            "/v1/certificates/renew",
            Some(renew(t, &phone)),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let new = cert_of(&v);
    assert_eq!(
        (new.user_id, &new.real_name, new.device_key),
        (cert.user_id, &cert.real_name, cert.device_key)
    );
    assert_eq!(new.expires_at, t + 365 * DAY);

    // After expiry renewal still works (expired phones can only browse until then).
    let t = cert.expires_at + 5 * DAY;
    s.set_time(t);
    let (st, _) = s
        .call(
            "POST",
            "/v1/certificates/renew",
            Some(renew(t, &phone)),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn end_to_end_certificate_stamp_review() {
    let s = server();
    let trust = s.trust().await;
    let phone = Arc::new(SoftwareSigner::generate());
    let mut node = Node::new(Store::new(), trust.clone(), phone.clone());
    node.set_identity(cert_of(&s.certificate("Kim Minji", &*phone).await.1))
        .unwrap();

    // Collect: the phone builds and signs the visit, the server stamps only the id.
    let place = gangnam();
    let fix = Fix {
        taken_at: T0,
        location: place.location,
        accuracy_m: 8,
    };
    let visit_id = node.collect(place, sha256(b"photo"), fix).unwrap();
    s.set_time(T0 + 120);
    let (st, v) = s
        .call(
            "POST",
            "/v1/stamps",
            Some(json!({ "visit_id": B64.encode(visit_id), "attestation": { "platform": "dev", "token": "ok" } })),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let stamp = Stamp::from_cbor(&B64.decode(v["stamp"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(stamp.stamp_at, T0 + 120);
    node.stamp_visit(&visit_id, stamp).unwrap();

    let id = node
        .write_review(
            &visit_id,
            &Draft {
                title: "Best cold noodles".into(),
                text: "Broth like ice.".into(),
                photo: None,
            },
            (T0 + 3600) * 1000,
        )
        .unwrap();
    let review = node.store().saved_review(&id).unwrap().review.clone();
    verify_review(&review, None, &trust, T0 + DAY).unwrap();

    // A stamp asked for a day and a half later is refused by the phone.
    let visit2 = node.collect(gangnam(), sha256(b"photo2"), fix).unwrap();
    s.set_time(T0 + 36 * 3600);
    let (_, v) = s
        .call("POST", "/v1/stamps", Some(json!({ "visit_id": B64.encode(visit2), "attestation": { "platform": "dev", "token": "ok" } })), None)
        .await;
    let late = Stamp::from_cbor(&B64.decode(v["stamp"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(
        node.stamp_visit(&visit2, late),
        Err(tbm_core::Error::StampTooLate)
    );
}

#[tokio::test]
async fn admin_revocation() {
    let s = server();
    let phone = SoftwareSigner::generate();
    let cert = cert_of(&s.certificate("Kim Minji", &phone).await.1);
    let uid = tbm_core::crypto::hex(&cert.user_id);

    let body = json!({ "user_id": uid });
    let (st, _) = s
        .call("POST", "/v1/admin/revoke", Some(body.clone()), None)
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let (st, _) = s
        .call(
            "POST",
            "/v1/admin/revoke",
            Some(body.clone()),
            Some("wrong-token-wrong-token-wrong-tok"),
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let (st, _) = s
        .call(
            "POST",
            "/v1/admin/revoke",
            Some(json!({ "user_id": "ff".repeat(16) })),
            Some(ADMIN),
        )
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    s.set_time(T0 + 50);
    let (st, v) = s
        .call("POST", "/v1/admin/revoke", Some(body), Some(ADMIN))
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["revoked"], true);

    let (_, v) = s.call("GET", "/v1/revocations", None, None).await;
    let list = RevocationList::from_cbor(&B64.decode(v["revocations"].as_str().unwrap()).unwrap())
        .unwrap();
    let mut trust = s.trust().await;
    trust.update_revocations(list).unwrap();
    assert!(trust.is_user_revoked(&cert.user_id));

    // A revoked person cannot get a new certificate, even on a new phone.
    let (st, _) = s
        .certificate("Kim Minji", &SoftwareSigner::generate())
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // Revoking one device key.
    let lee_phone = SoftwareSigner::generate();
    s.certificate("Lee Jiwoo", &lee_phone).await;
    let (st, _) = s
        .call(
            "POST",
            "/v1/admin/revoke",
            Some(json!({ "device_key": B64.encode(lee_phone.public_key().0) })),
            Some(ADMIN),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    let (_, v) = s.call("GET", "/v1/revocations", None, None).await;
    let list = RevocationList::from_cbor(&B64.decode(v["revocations"].as_str().unwrap()).unwrap())
        .unwrap();
    assert_eq!(list.keys.len(), 1);
}

#[test]
fn server_key_file_is_created_once_and_private() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys/server.key");
    let a = tbm_server::keys::load_or_create(&path).unwrap();
    let b = tbm_server::keys::load_or_create(&path).unwrap();
    assert_eq!(a.public_key(), b.public_key());
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}
