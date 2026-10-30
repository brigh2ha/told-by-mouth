//! The chain of trust. Our server's public keys are built into the app; from
//! them a phone checks certificates, stamps and the revocation list, offline.

use std::collections::BTreeMap;

use crate::cbor::{Cbor, Dec, Enc};
use crate::crypto::{Hash, PublicKey};
use crate::error::Error;
use crate::limits::{Time, CLOCK_DRIFT, REAL_NAME_MAX, REVOCATIONS_STALE, STAMP_WINDOW};
use crate::model::{check_len, Certificate, RevocationList, Stamp, UserId};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trust {
    /// Server key id to key. Built into the app.
    server_keys: BTreeMap<u8, PublicKey>,
    revocations: Option<RevocationList>,
}

impl Trust {
    pub fn new(server_keys: impl IntoIterator<Item = (u8, PublicKey)>) -> Self {
        Self {
            server_keys: server_keys.into_iter().collect(),
            revocations: None,
        }
    }

    pub fn server_key(&self, id: u8) -> Result<&PublicKey, Error> {
        self.server_keys.get(&id).ok_or(Error::UnknownServerKey(id))
    }

    /// The server signature is valid and the fields are well formed. Says
    /// nothing about time or revocation.
    pub fn verify_certificate(&self, cert: &Certificate) -> Result<(), Error> {
        check_len("real name", &cert.real_name, 1, REAL_NAME_MAX)?;
        if cert.expires_at <= cert.issued_at {
            return Err(Error::CertificateNotValid);
        }
        self.server_key(cert.server_key_id)?.verify(
            &cert.signed_bytes(),
            &cert.server_sig,
            "certificate",
        )
    }

    /// Valid signature, valid at `at`, and not revoked for something done
    /// at `at`.
    pub fn check_certificate_at(&self, cert: &Certificate, at: Time) -> Result<(), Error> {
        self.verify_certificate(cert)?;
        if at + CLOCK_DRIFT < cert.issued_at || at > cert.expires_at {
            return Err(Error::CertificateNotValid);
        }
        if self.is_revoked(cert, at) {
            return Err(Error::Revoked);
        }
        Ok(())
    }

    /// Whether something this certificate signed at `at` must be rejected.
    /// A revoked person is rejected for everything; a revoked key only from
    /// its `since` time on.
    pub fn is_revoked(&self, cert: &Certificate, at: Time) -> bool {
        let Some(list) = &self.revocations else {
            return false;
        };
        self.is_user_revoked(&cert.user_id)
            || list
                .keys
                .iter()
                .any(|k| k.key == cert.device_key && at >= k.since)
    }

    pub fn is_user_revoked(&self, user: &UserId) -> bool {
        self.revocations
            .as_ref()
            .is_some_and(|l| l.users.contains(user))
    }

    /// Checks a stamp's signature and that it came within 24 hours of the
    /// photo (and not before it, allowing for clock drift).
    pub fn verify_stamp(
        &self,
        visit_id: &Hash,
        taken_at: Time,
        stamp: &Stamp,
    ) -> Result<(), Error> {
        self.server_key(stamp.server_key_id)?.verify(
            &Stamp::signed_bytes(visit_id, stamp.stamp_at),
            &stamp.stamp_sig,
            "stamp",
        )?;
        if stamp.stamp_at + CLOCK_DRIFT < taken_at {
            return Err(Error::InFuture);
        }
        if stamp.stamp_at > taken_at + STAMP_WINDOW {
            return Err(Error::StampTooLate);
        }
        Ok(())
    }

    pub fn verify_revocations(&self, list: &RevocationList) -> Result<(), Error> {
        self.server_key(list.server_key_id)?.verify(
            &list.signed_bytes(),
            &list.server_sig,
            "revocation list",
        )
    }

    /// Installs a newer signed revocation list. Returns false (and changes
    /// nothing) if it is not newer than the one held.
    pub fn update_revocations(&mut self, list: RevocationList) -> Result<bool, Error> {
        self.verify_revocations(&list)?;
        if self
            .revocations
            .as_ref()
            .is_some_and(|cur| cur.issued_at >= list.issued_at)
        {
            return Ok(false);
        }
        self.revocations = Some(list);
        Ok(true)
    }

    pub fn revocations(&self) -> Option<&RevocationList> {
        self.revocations.as_ref()
    }

    /// The app warns (but keeps working) when the list is this old.
    pub fn revocations_stale(&self, now: Time) -> bool {
        match &self.revocations {
            Some(l) => now > l.issued_at + REVOCATIONS_STALE,
            None => true,
        }
    }
}

impl Cbor for Trust {
    fn encode(&self, e: &mut Enc) {
        e.array(2).array(self.server_keys.len());
        for (id, key) in &self.server_keys {
            e.array(2).u64(*id as u64).item(key);
        }
        e.opt(&self.revocations);
    }
    fn decode(d: &mut Dec<'_>) -> Result<Self, Error> {
        d.expect_array(2)?;
        let n = d.array()?;
        let mut server_keys = BTreeMap::new();
        for _ in 0..n {
            d.expect_array(2)?;
            server_keys.insert(d.u8()?, d.item()?);
        }
        let trust = Self {
            server_keys,
            revocations: d.opt()?,
        };
        if let Some(list) = &trust.revocations {
            trust.verify_revocations(list)?;
        }
        Ok(trust)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Signer, SoftwareSigner};
    use crate::limits::DAY;
    use crate::model::RevokedKey;

    const T0: Time = 1_790_000_000;

    fn setup() -> (SoftwareSigner, Trust, SoftwareSigner, Certificate) {
        let server = SoftwareSigner::generate();
        let trust = Trust::new([(1, server.public_key())]);
        let device = SoftwareSigner::generate();
        let cert =
            Certificate::issue(&server, 1, [9; 16], "Kim Minji", device.public_key(), T0).unwrap();
        (server, trust, device, cert)
    }

    #[test]
    fn certificate_checks() {
        let (_server, trust, _device, cert) = setup();
        trust.check_certificate_at(&cert, T0 + DAY).unwrap();
        assert_eq!(
            trust.check_certificate_at(&cert, T0 + 400 * DAY),
            Err(Error::CertificateNotValid)
        );
        assert_eq!(
            trust.check_certificate_at(&cert, T0 - DAY),
            Err(Error::CertificateNotValid)
        );

        let mut forged = cert.clone();
        forged.real_name = "Lee Jiwoo".into();
        assert_eq!(
            trust.verify_certificate(&forged),
            Err(Error::BadSignature("certificate"))
        );

        let mut unknown = cert.clone();
        unknown.server_key_id = 7;
        assert_eq!(
            trust.verify_certificate(&unknown),
            Err(Error::UnknownServerKey(7))
        );

        // A certificate signed by some other key is rejected.
        let rogue = SoftwareSigner::generate();
        let fake =
            Certificate::issue(&rogue, 1, [9; 16], "Kim Minji", cert.device_key, T0).unwrap();
        assert!(trust.verify_certificate(&fake).is_err());
    }

    #[test]
    fn revocation_by_user_and_by_key() {
        let (server, mut trust, _device, cert) = setup();
        assert!(trust.revocations_stale(T0));

        let by_key = RevocationList::issue(
            &server,
            1,
            T0 + 10,
            vec![],
            vec![RevokedKey {
                key: cert.device_key,
                since: T0 + 5 * DAY,
            }],
        )
        .unwrap();
        assert!(trust.update_revocations(by_key.clone()).unwrap());
        // Written before the key was replaced: still fine.
        trust.check_certificate_at(&cert, T0 + DAY).unwrap();
        assert_eq!(
            trust.check_certificate_at(&cert, T0 + 6 * DAY),
            Err(Error::Revoked)
        );
        // Same list again is not newer.
        assert!(!trust.update_revocations(by_key).unwrap());

        let by_user =
            RevocationList::issue(&server, 1, T0 + 20, vec![cert.user_id], vec![]).unwrap();
        assert!(trust.update_revocations(by_user).unwrap());
        assert_eq!(
            trust.check_certificate_at(&cert, T0 + DAY),
            Err(Error::Revoked)
        );

        // Forged lists are refused and survive encoding only when valid.
        let mut forged = RevocationList::issue(&server, 1, T0 + 30, vec![], vec![]).unwrap();
        forged.users.push([1; 16]);
        assert!(trust.update_revocations(forged).is_err());
        let back = Trust::from_cbor(&trust.to_cbor()).unwrap();
        assert_eq!(back, trust);
    }
}
