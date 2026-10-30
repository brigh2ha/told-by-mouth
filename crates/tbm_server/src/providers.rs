//! Pluggable checks the server relies on: the real-name identity provider
//! and the device-integrity attestation (Apple App Attest, Google Play
//! Integrity). The launch country and provider are not decided yet, so only
//! development stubs exist. They accept anything and are enabled only with
//! `dev_mode = true`.

/// What an identity provider vouches for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPerson {
    /// The real name to put in the certificate.
    pub real_name: String,
    /// The provider's stable reference for this person (for example the
    /// Korean CI value). Only a hash of it is stored, to keep one user_id
    /// per person.
    pub person_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderError {
    /// The check ran and said no.
    Rejected(String),
    /// No provider is configured for this kind of request.
    NotConfigured,
}

/// A real-name identity check, such as PASS in Korea or an ID document scan.
pub trait IdentityProvider: Send + Sync {
    /// `provider` names which check the phone used and `token` is its result.
    fn verify(&self, provider: &str, token: &str) -> Result<VerifiedPerson, ProviderError>;
}

/// A device-integrity check bound to `binding` (the hash of the public key
/// for certificates, the visit_id for stamps).
///
/// TODO before launch: App Attest and Play Integrity both need a fresh
/// server-issued challenge folded into `binding`; add a challenge endpoint
/// when the real implementations are written.
pub trait Attestation: Send + Sync {
    fn verify(&self, platform: &str, token: &str, binding: &[u8]) -> Result<(), ProviderError>;
}

/// Used when nothing is configured: every request is refused.
pub struct NotConfigured;

impl IdentityProvider for NotConfigured {
    fn verify(&self, _: &str, _: &str) -> Result<VerifiedPerson, ProviderError> {
        Err(ProviderError::NotConfigured)
    }
}

impl Attestation for NotConfigured {
    fn verify(&self, _: &str, _: &str, _: &[u8]) -> Result<(), ProviderError> {
        Err(ProviderError::NotConfigured)
    }
}

/// DEVELOPMENT STUB. Provider "dev"; the token is the real name itself and
/// also the person reference. Anyone can claim any name. Never use in
/// production.
pub struct DevIdentity;

impl IdentityProvider for DevIdentity {
    fn verify(&self, provider: &str, token: &str) -> Result<VerifiedPerson, ProviderError> {
        if provider != "dev" {
            return Err(ProviderError::NotConfigured);
        }
        let name = token.trim();
        if name.is_empty() {
            return Err(ProviderError::Rejected("empty name".into()));
        }
        Ok(VerifiedPerson {
            real_name: name.to_owned(),
            person_ref: format!("dev:{name}"),
        })
    }
}

/// DEVELOPMENT STUB. Accepts platform "dev" with token "ok". Never use in
/// production.
pub struct DevAttestation;

impl Attestation for DevAttestation {
    fn verify(&self, platform: &str, token: &str, _: &[u8]) -> Result<(), ProviderError> {
        match (platform, token) {
            ("dev", "ok") => Ok(()),
            ("dev", _) => Err(ProviderError::Rejected(
                "dev attestation token must be \"ok\"".into(),
            )),
            _ => Err(ProviderError::NotConfigured),
        }
    }
}
