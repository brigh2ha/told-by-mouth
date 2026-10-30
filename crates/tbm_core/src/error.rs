//! Every way a rule can say no. The screens turn these into friendly text.

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    #[error("could not read data: {0}")]
    Decode(String),
    #[error("invalid public key")]
    BadKey,
    #[error("signature does not match ({0})")]
    BadSignature(&'static str),
    #[error("the secure chip could not sign: {0}")]
    SignerFailed(String),
    #[error("id does not match the contents ({0})")]
    IdMismatch(&'static str),
    #[error("unknown server key {0}")]
    UnknownServerKey(u8),

    #[error("certificate is not valid at that time")]
    CertificateNotValid,
    #[error("certificate has expired; renew it to write, share, save or trade")]
    CertificateExpired,
    #[error("this person's certificate has been revoked")]
    Revoked,
    #[error("this person is blocked")]
    Blocked,
    #[error("no identity yet")]
    NoIdentity,

    #[error("{field} must be {min} to {max} characters")]
    Length {
        field: &'static str,
        min: usize,
        max: usize,
    },
    #[error("invalid location")]
    BadLocation,
    #[error("location fix is {accuracy_m} m; move outside and try again")]
    FixTooCoarse { accuracy_m: u32 },
    #[error("restaurant is {distance_m} m away, more than the allowed {allowed_m} m")]
    PlaceTooFar { distance_m: u32, allowed_m: u32 },
    #[error("photo is larger than {max} bytes")]
    PhotoTooLarge { max: usize },
    #[error("photo does not match its hash")]
    PhotoMismatch,

    #[error("visit has no server stamp yet")]
    NotStamped,
    #[error("stamp came more than 24 hours after the photo")]
    StampTooLate,
    #[error("only a visit you collected yourself can be reviewed")]
    NotMyVisit,
    #[error("visit is older than 30 days")]
    VisitTooOld,
    #[error("this visit already has a review")]
    AlreadyReviewed,
    #[error("time is in the future")]
    InFuture,

    #[error("list entry does not match the review ({0})")]
    EntryMismatch(&'static str),
    #[error("you have saved the most reviews allowed; remove some first")]
    SavedLimitReached,
    #[error("not found")]
    NotFound,

    #[error("protocol error: {0}")]
    Protocol(&'static str),
    #[error("reply was too slow")]
    TooSlow,
    #[error("too many requests")]
    RateLimited,
    #[error("trade: {0}")]
    Trade(&'static str),
}
