//! SHA-256, ECDSA P-256 keys and signatures, and the purpose tags.
//!
//! P-256 is the one curve that both the iPhone Secure Enclave and Android
//! StrongBox support. Public keys are 33-byte compressed SEC1 points and
//! signatures are 64 bytes (`r || s`). A signature always covers
//! `SHA-256(message)`, the same as Apple's `ecdsaSignatureMessageX962SHA256`
//! and Android's `SHA256withECDSA`; the native side converts their DER output
//! to the 64-byte form.

use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature as P256Signature, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::cbor::{Cbor, Dec, Enc};
use crate::error::Error;

pub type Hash = [u8; 32];

pub fn sha256(data: &[u8]) -> Hash {
    Sha256::digest(data).into()
}

/// Fills a buffer with random bytes from the operating system.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

/// Purpose tags. Every signature signs one of these first, so a signature
/// made for one purpose can never be reused for another. Hash preimages get
/// their own tags too.
pub mod tag {
    pub const CERTIFICATE: &str = "tbm/cert/1";
    pub const VISIT: &str = "tbm/visit/1";
    pub const STAMP: &str = "tbm/stamp/1";
    pub const REVIEW: &str = "tbm/review/1";
    pub const HELLO: &str = "tbm/hello/1";
    pub const TRADE: &str = "tbm/trade/1";
    pub const REVOCATIONS: &str = "tbm/revocations/1";
    pub const RENEW: &str = "tbm/renew/1";

    pub const VISIT_ID: &str = "tbm/visit-id/1";
    pub const REVIEW_ID: &str = "tbm/review-id/1";
    pub const CARD_ID: &str = "tbm/card-id/1";
    pub const REVIEWER_ID: &str = "tbm/reviewer-id/1";
    pub const MEETING_ID: &str = "tbm/meeting-id/1";
}

/// A compressed P-256 public key (33 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey(pub [u8; 33]);

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({})", hex(&self.0[..6]))
    }
}

impl PublicKey {
    /// Accepts a compressed or uncompressed SEC1 key and stores it
    /// compressed. Fails if it is not a point on the curve.
    pub fn from_sec1(bytes: &[u8]) -> Result<Self, Error> {
        let vk = VerifyingKey::from_sec1_bytes(bytes).map_err(|_| Error::BadKey)?;
        let point = vk.to_encoded_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(point.as_bytes());
        Ok(Self(out))
    }

    /// Checks `sig` over `message`. `what` names the signature in errors.
    pub fn verify(&self, message: &[u8], sig: &Signature, what: &'static str) -> Result<(), Error> {
        let vk = VerifyingKey::from_sec1_bytes(&self.0).map_err(|_| Error::BadKey)?;
        let s = P256Signature::from_slice(&sig.0).map_err(|_| Error::BadSignature(what))?;
        vk.verify(message, &s)
            .map_err(|_| Error::BadSignature(what))
    }
}

impl Cbor for PublicKey {
    fn encode(&self, e: &mut Enc) {
        e.bytes(&self.0);
    }
    fn decode(d: &mut Dec<'_>) -> Result<Self, Error> {
        // Validate the point once, at the edge, and accept only the
        // compressed form so one key has one encoding.
        let raw: [u8; 33] = d.fixed()?;
        let key = Self::from_sec1(&raw)?;
        if key.0 != raw {
            return Err(Error::BadKey);
        }
        Ok(key)
    }
}

/// A 64-byte ECDSA P-256 signature (`r || s`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signature({}…)", hex(&self.0[..6]))
    }
}

impl Cbor for Signature {
    fn encode(&self, e: &mut Enc) {
        e.bytes(&self.0);
    }
    fn decode(d: &mut Dec<'_>) -> Result<Self, Error> {
        d.fixed().map(Signature)
    }
}

/// The phone's secure chip (or the server's key). The private key never
/// leaves the implementation; the core only asks it to sign.
pub trait Signer: Send + Sync {
    fn public_key(&self) -> PublicKey;
    /// ECDSA P-256 over SHA-256 of `message`, as 64 bytes.
    fn sign(&self, message: &[u8]) -> Result<Signature, Error>;
}

impl<T: Signer + ?Sized> Signer for std::sync::Arc<T> {
    fn public_key(&self) -> PublicKey {
        (**self).public_key()
    }
    fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        (**self).sign(message)
    }
}

/// A P-256 key held in memory. Used by the server and by tests; the phones
/// use the Secure Enclave or StrongBox instead.
pub struct SoftwareSigner {
    key: SigningKey,
}

impl SoftwareSigner {
    pub fn generate() -> Self {
        Self {
            key: SigningKey::random(&mut OsRng),
        }
    }

    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, Error> {
        SigningKey::from_slice(bytes)
            .map(|key| Self { key })
            .map_err(|_| Error::BadKey)
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.key.to_bytes().into()
    }
}

impl Signer for SoftwareSigner {
    fn public_key(&self) -> PublicKey {
        let point = self.key.verifying_key().to_encoded_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(point.as_bytes());
        PublicKey(out)
    }

    fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        let sig: P256Signature = self.key.sign(message);
        Ok(Signature(sig.to_bytes().into()))
    }
}

/// The exact bytes a signature covers: a CBOR array of the purpose tag
/// followed by the payload items written by `f`.
pub fn signed_message(tag: &str, items: usize, f: impl FnOnce(&mut Enc)) -> Vec<u8> {
    let mut e = Enc::new();
    e.array(items + 1).text(tag);
    f(&mut e);
    e.finish()
}

/// SHA-256 of a tagged CBOR array, used for every id.
pub fn tagged_hash(tag: &str, items: usize, f: impl FnOnce(&mut Enc)) -> Hash {
    sha256(&signed_message(tag, items, f))
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let s = SoftwareSigner::generate();
        let msg = signed_message(tag::REVIEW, 1, |e| {
            e.bytes(&[7; 32]);
        });
        let sig = s.sign(&msg).unwrap();
        s.public_key().verify(&msg, &sig, "test").unwrap();

        let mut other = msg.clone();
        *other.last_mut().unwrap() ^= 1;
        assert_eq!(
            s.public_key().verify(&other, &sig, "test"),
            Err(Error::BadSignature("test"))
        );
    }

    #[test]
    fn purpose_tags_separate_signatures() {
        let s = SoftwareSigner::generate();
        let a = signed_message(tag::REVIEW, 1, |e| {
            e.bytes(&[1; 32]);
        });
        let b = signed_message(tag::VISIT, 1, |e| {
            e.bytes(&[1; 32]);
        });
        let sig = s.sign(&a).unwrap();
        assert!(s.public_key().verify(&b, &sig, "x").is_err());
    }

    #[test]
    fn keys_are_33_bytes_and_round_trip() {
        let s = SoftwareSigner::generate();
        let pk = s.public_key();
        assert!(pk.0[0] == 2 || pk.0[0] == 3);
        assert_eq!(PublicKey::from_cbor(&pk.to_cbor()).unwrap(), pk);
        let s2 = SoftwareSigner::from_secret_bytes(&s.secret_bytes()).unwrap();
        assert_eq!(s2.public_key(), pk);
        assert_eq!(PublicKey::from_sec1(&[9; 33]), Err(Error::BadKey));
    }
}
