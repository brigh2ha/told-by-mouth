//! The meeting handshake (spec section 5): HELLO, certificate checks, PROVE.

use std::collections::BTreeSet;

use crate::crypto::{sha256, signed_message, tag, Signature, Signer};
use crate::error::Error;
use crate::limits::{Time, CLOCK_DRIFT, PROTOCOL_VERSION, PROVE_TIMEOUT_MS};
use crate::model::{Certificate, MeetingId, UserId};
use crate::trust::Trust;
use crate::wire::{Hello, Message};

/// What I know about the other person once the handshake succeeds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Met {
    pub certificate: Certificate,
    pub catalog_version: u32,
    pub meeting_id: MeetingId,
    /// Their certificate has expired: they may browse but not share, save
    /// or trade.
    pub browse_only: bool,
}

#[derive(Debug)]
enum State {
    AwaitHello,
    AwaitProve { hello: Hello, since_ms: u64 },
    Done(Met),
    Failed,
}

/// One handshake on one link. Both phones run the same steps.
#[derive(Debug)]
pub struct Handshake {
    my_nonce: [u8; 16],
    state: State,
}

/// The bytes PROVE signs: the tag, the other's nonce, then my own.
pub fn prove_bytes(their_nonce: &[u8; 16], my_nonce: &[u8; 16]) -> Vec<u8> {
    signed_message(tag::HELLO, 2, |e| {
        e.bytes(their_nonce).bytes(my_nonce);
    })
}

/// First 16 bytes of the hash of both nonces, smaller first.
pub fn meeting_id(a: &[u8; 16], b: &[u8; 16]) -> MeetingId {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut both = [0u8; 32];
    both[..16].copy_from_slice(lo);
    both[16..].copy_from_slice(hi);
    sha256(&both)[..16].try_into().unwrap()
}

/// Checks the other person's certificate at the handshake: server signature
/// valid, not revoked, not blocked, not me. Returns whether it has expired
/// (browse only).
pub fn check_peer_certificate(
    cert: &Certificate,
    trust: &Trust,
    blocked: &BTreeSet<UserId>,
    me: &UserId,
    now: Time,
) -> Result<bool, Error> {
    trust.verify_certificate(cert)?;
    if now + CLOCK_DRIFT < cert.issued_at {
        return Err(Error::CertificateNotValid);
    }
    if trust.is_revoked(cert, now) {
        return Err(Error::Revoked);
    }
    if blocked.contains(&cert.user_id) {
        return Err(Error::Blocked);
    }
    if &cert.user_id == me {
        return Err(Error::Protocol("cannot meet yourself"));
    }
    Ok(now > cert.expires_at)
}

impl Handshake {
    /// Starts a handshake and returns the HELLO to send.
    pub fn start(me: &Certificate, catalog_version: u32, nonce: [u8; 16]) -> (Self, Message) {
        let hello = Message::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            certificate: me.clone(),
            nonce,
            catalog_version,
        });
        (
            Self {
                my_nonce: nonce,
                state: State::AwaitHello,
            },
            hello,
        )
    }

    pub fn met(&self) -> Option<&Met> {
        match &self.state {
            State::Done(m) => Some(m),
            _ => None,
        }
    }

    /// Handles their HELLO and returns my PROVE. The PROVE timer starts now.
    #[allow(clippy::too_many_arguments)]
    pub fn on_hello(
        &mut self,
        hello: Hello,
        signer: &dyn Signer,
        trust: &Trust,
        blocked: &BTreeSet<UserId>,
        me: &UserId,
        now_ms: u64,
    ) -> Result<Message, Error> {
        let result = (|| {
            if !matches!(self.state, State::AwaitHello) {
                return Err(Error::Protocol("unexpected HELLO"));
            }
            if hello.protocol != PROTOCOL_VERSION {
                return Err(Error::Protocol("unsupported protocol version"));
            }
            if hello.nonce == self.my_nonce {
                return Err(Error::Protocol("nonce reused"));
            }
            check_peer_certificate(&hello.certificate, trust, blocked, me, now_ms / 1000)?;
            let sig = signer.sign(&prove_bytes(&hello.nonce, &self.my_nonce))?;
            Ok((Message::Prove(sig), hello))
        })();
        match result {
            Ok((prove, hello)) => {
                self.state = State::AwaitProve {
                    hello,
                    since_ms: now_ms,
                };
                Ok(prove)
            }
            Err(e) => {
                self.state = State::Failed;
                Err(e)
            }
        }
    }

    /// Handles their PROVE. On success the meeting is open.
    pub fn on_prove(&mut self, sig: &Signature, now_ms: u64) -> Result<&Met, Error> {
        let State::AwaitProve { hello, since_ms } =
            std::mem::replace(&mut self.state, State::Failed)
        else {
            return Err(Error::Protocol("unexpected PROVE"));
        };
        if now_ms.saturating_sub(since_ms) > PROVE_TIMEOUT_MS {
            return Err(Error::TooSlow);
        }
        hello.certificate.device_key.verify(
            &prove_bytes(&self.my_nonce, &hello.nonce),
            sig,
            "hello",
        )?;
        let browse_only = now_ms / 1000 > hello.certificate.expires_at;
        self.state = State::Done(Met {
            meeting_id: meeting_id(&self.my_nonce, &hello.nonce),
            catalog_version: hello.catalog_version,
            certificate: hello.certificate,
            browse_only,
        });
        Ok(self.met().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::DAY;
    use crate::testkit::*;

    fn hello_of(m: Message) -> Hello {
        match m {
            Message::Hello(h) => h,
            _ => panic!(),
        }
    }
    fn sig_of(m: Message) -> Signature {
        match m {
            Message::Prove(s) => s,
            _ => panic!(),
        }
    }

    #[test]
    fn both_sides_agree_on_the_meeting() {
        let w = World::new();
        let (kim, lee) = (w.person("Kim"), w.person("Lee"));
        let none = BTreeSet::new();
        let now = T0 * 1000;
        let (mut a, ha) = Handshake::start(&kim.cert, 3, [1; 16]);
        let (mut b, hb) = Handshake::start(&lee.cert, 9, [2; 16]);
        let pa = a
            .on_hello(
                hello_of(hb),
                &*kim.key,
                &w.trust,
                &none,
                &kim.user_id(),
                now,
            )
            .unwrap();
        let pb = b
            .on_hello(
                hello_of(ha),
                &*lee.key,
                &w.trust,
                &none,
                &lee.user_id(),
                now,
            )
            .unwrap();
        let ma = a.on_prove(&sig_of(pb), now + 100).unwrap().clone();
        let mb = b.on_prove(&sig_of(pa), now + 100).unwrap().clone();
        assert_eq!(ma.meeting_id, mb.meeting_id);
        assert_eq!(ma.meeting_id, meeting_id(&[2; 16], &[1; 16]));
        assert_eq!(ma.certificate, lee.cert);
        assert_eq!(ma.catalog_version, 9);
        assert!(!ma.browse_only);
    }

    #[test]
    fn failures() {
        let w = World::new();
        let (kim, lee) = (w.person("Kim"), w.person("Lee"));
        let none = BTreeSet::new();
        let now = T0 * 1000;

        // Too slow.
        let (mut a, _) = Handshake::start(&kim.cert, 0, [1; 16]);
        let (mut b, hb) = Handshake::start(&lee.cert, 0, [2; 16]);
        a.on_hello(
            hello_of(hb.clone()),
            &*kim.key,
            &w.trust,
            &none,
            &kim.user_id(),
            now,
        )
        .unwrap();
        let pb = sig_of(
            b.on_hello(
                hello_of(Handshake::start(&kim.cert, 0, [1; 16]).1),
                &*lee.key,
                &w.trust,
                &none,
                &lee.user_id(),
                now,
            )
            .unwrap(),
        );
        assert_eq!(a.on_prove(&pb, now + 501).unwrap_err(), Error::TooSlow);

        // A PROVE replayed from another meeting (different nonce) fails.
        let (mut a, _) = Handshake::start(&kim.cert, 0, [7; 16]);
        a.on_hello(
            hello_of(hb.clone()),
            &*kim.key,
            &w.trust,
            &none,
            &kim.user_id(),
            now,
        )
        .unwrap();
        assert_eq!(
            a.on_prove(&pb, now + 10).unwrap_err(),
            Error::BadSignature("hello")
        );

        // Blocked, revoked, self, forged certificate.
        let blocked: BTreeSet<_> = [lee.user_id()].into();
        let (mut a, _) = Handshake::start(&kim.cert, 0, [1; 16]);
        assert_eq!(
            a.on_hello(
                hello_of(hb.clone()),
                &*kim.key,
                &w.trust,
                &blocked,
                &kim.user_id(),
                now
            )
            .unwrap_err(),
            Error::Blocked
        );
        let mut trust = w.trust.clone();
        trust
            .update_revocations(w.revoke_users(&[lee.user_id()], T0))
            .unwrap();
        let (mut a, _) = Handshake::start(&kim.cert, 0, [1; 16]);
        assert_eq!(
            a.on_hello(
                hello_of(hb.clone()),
                &*kim.key,
                &trust,
                &none,
                &kim.user_id(),
                now
            )
            .unwrap_err(),
            Error::Revoked
        );
        let (mut a, _) = Handshake::start(&lee.cert, 0, [1; 16]);
        assert!(a
            .on_hello(
                hello_of(hb.clone()),
                &*lee.key,
                &w.trust,
                &none,
                &lee.user_id(),
                now
            )
            .is_err());
        let mut forged = hello_of(hb);
        forged.certificate.real_name = "Somebody Famous".into();
        let (mut a, _) = Handshake::start(&kim.cert, 0, [1; 16]);
        assert!(a
            .on_hello(forged, &*kim.key, &w.trust, &none, &kim.user_id(), now)
            .is_err());
    }

    #[test]
    fn expired_certificate_is_browse_only() {
        let w = World::new();
        let kim = w.person("Kim");
        let old = w.person_at("Old", T0 - 400 * DAY);
        let none = BTreeSet::new();
        let now = T0 * 1000;
        let (mut a, _) = Handshake::start(&kim.cert, 0, [1; 16]);
        let (mut b, hb) = Handshake::start(&old.cert, 0, [2; 16]);
        let (_, ha) = Handshake::start(&kim.cert, 0, [1; 16]);
        a.on_hello(
            hello_of(hb),
            &*kim.key,
            &w.trust,
            &none,
            &kim.user_id(),
            now,
        )
        .unwrap();
        let pb = sig_of(
            b.on_hello(
                hello_of(ha),
                &*old.key,
                &w.trust,
                &none,
                &old.user_id(),
                now,
            )
            .unwrap(),
        );
        assert!(a.on_prove(&pb, now + 50).unwrap().browse_only);
    }
}
