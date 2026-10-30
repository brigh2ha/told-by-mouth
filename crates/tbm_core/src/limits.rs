//! Every number the rules use, in one place. Several are marked "to tune" in
//! the spec; change them here and both apps follow.

/// Seconds since 1970, UTC.
pub type Time = u64;

pub const MINUTE: Time = 60;
pub const HOUR: Time = 60 * MINUTE;
pub const DAY: Time = 24 * HOUR;

/// Allowed clock difference between phones (and between a phone and the server).
pub const CLOCK_DRIFT: Time = 10 * MINUTE;

/// A certificate is valid for one year.
pub const CERTIFICATE_VALIDITY: Time = 365 * DAY;
/// Renewal is allowed in the last 30 days before expiry (and after it).
pub const RENEW_WINDOW: Time = 30 * DAY;

/// The server stamp must come within 24 hours of the photo.
pub const STAMP_WINDOW: Time = 24 * HOUR;
/// A review must be written within 30 days of the visit (to tune).
pub const REVIEW_WINDOW: Time = 30 * DAY;

pub const REAL_NAME_MAX: usize = 50;
pub const TITLE_MAX: usize = 40;
pub const TEXT_MAX: usize = 1000;
/// Not in the spec; bounds the size of a list entry.
pub const PLACE_NAME_MAX: usize = 100;
/// Not in the spec; map-service ids are short.
pub const PLACE_ID_MAX_BYTES: usize = 128;
/// The small review photo.
pub const PHOTO_MAX_BYTES: usize = 100 * 1024;

/// At most this many reviews of one restaurant appear in the list.
pub const MAX_PER_RESTAURANT: usize = 3;
/// Reviews saved from others (to tune). Own reviews do not count.
pub const SAVED_LIMIT: usize = 1000;

/// A PROVE slower than this fails the handshake (to tune).
pub const PROVE_TIMEOUT_MS: u64 = 500;
/// A failed handshake ignores that advertisement token this long.
pub const IGNORE_TOKEN_SECS: Time = 10 * MINUTE;
/// Try the next holder after this long without an answer.
pub const HOLDER_RETRY_MS: u64 = 10_000;
/// GET_REVIEW requests served per person per minute.
pub const GET_REVIEW_PER_MINUTE: usize = 30;
/// Rebuild the list after moving this far.
pub const RELIST_MOVE_M: u32 = 50;
/// Warn when the revocation list is older than this.
pub const REVOCATIONS_STALE: Time = 30 * DAY;

/// BLE link chunk size (the largest ATT payload we use).
pub const LINK_CHUNK: usize = 512;
/// Largest message we accept (3-byte length allows 16 MB; we cap lower).
pub const MAX_MESSAGE_BYTES: usize = 1 << 20;

/// The meeting protocol version sent in HELLO.
pub const PROTOCOL_VERSION: u16 = 1;
