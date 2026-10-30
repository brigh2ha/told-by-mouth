//! The data structures from the spec, with their exact encodings, ids and
//! the bytes each signature covers. Rules that decide whether a value is
//! acceptable live in `trust`, `collect`, `review` and `list`.

use crate::cbor::{Cbor, Dec, Enc};
use crate::crypto::{sha256, signed_message, tag, tagged_hash, Hash, PublicKey, Signature, Signer};
use crate::error::Error;
use crate::geo::GeoPoint;
use crate::limits::{Time, CERTIFICATE_VALIDITY};

/// 16 random bytes that stay the same for a person.
pub type UserId = [u8; 16];
/// Short hash of a reviewer's device key (8 bytes), used in list entries.
pub type ReviewerId = [u8; 8];
/// First 16 bytes of the hash of both handshake nonces.
pub type MeetingId = [u8; 16];

/// Counts characters (Unicode scalar values) and checks the range.
pub fn check_len(field: &'static str, s: &str, min: usize, max: usize) -> Result<(), Error> {
    let n = s.chars().count();
    if n < min || n > max {
        return Err(Error::Length { field, min, max });
    }
    Ok(())
}

// ---------------------------------------------------------------- Certificate

/// Issued by our identity server: "this device key belongs to this real name".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub user_id: UserId,
    pub real_name: String,
    pub device_key: PublicKey,
    pub issued_at: Time,
    pub expires_at: Time,
    pub server_key_id: u8,
    pub server_sig: Signature,
}

impl Certificate {
    /// What the server signs.
    pub fn signed_bytes(&self) -> Vec<u8> {
        signed_message(tag::CERTIFICATE, 6, |e| {
            e.bytes(&self.user_id)
                .text(&self.real_name)
                .item(&self.device_key)
                .u64(self.issued_at)
                .u64(self.expires_at)
                .u64(self.server_key_id as u64);
        })
    }

    /// Server side: builds and signs a certificate valid for one year.
    pub fn issue(
        server: &dyn Signer,
        server_key_id: u8,
        user_id: UserId,
        real_name: &str,
        device_key: PublicKey,
        issued_at: Time,
    ) -> Result<Self, Error> {
        let mut cert = Certificate {
            user_id,
            real_name: real_name.to_owned(),
            device_key,
            issued_at,
            expires_at: issued_at + CERTIFICATE_VALIDITY,
            server_key_id,
            server_sig: Signature([0; 64]),
        };
        cert.server_sig = server.sign(&cert.signed_bytes())?;
        Ok(cert)
    }

    /// What the phone signs with its device key to renew this certificate:
    /// the tag, the hash of the current certificate and the request time.
    pub fn renew_request_bytes(&self, signed_at: Time) -> Vec<u8> {
        let cert_hash = sha256(&self.to_cbor());
        signed_message(tag::RENEW, 2, |e| {
            e.bytes(&cert_hash).u64(signed_at);
        })
    }

    /// The short id that list entries carry for "one review per reviewer".
    pub fn reviewer_id(&self) -> ReviewerId {
        reviewer_id(&self.device_key)
    }
}

pub fn reviewer_id(key: &PublicKey) -> ReviewerId {
    let h = tagged_hash(tag::REVIEWER_ID, 1, |e| {
        e.item(key);
    });
    h[..8].try_into().unwrap()
}

impl Cbor for Certificate {
    fn encode(&self, e: &mut Enc) {
        e.array(7)
            .bytes(&self.user_id)
            .text(&self.real_name)
            .item(&self.device_key)
            .u64(self.issued_at)
            .u64(self.expires_at)
            .u64(self.server_key_id as u64)
            .item(&self.server_sig);
    }
    fn decode(d: &mut Dec<'_>) -> Result<Self, Error> {
        d.expect_array(7)?;
        Ok(Self {
            user_id: d.fixed()?,
            real_name: d.string()?,
            device_key: d.item()?,
            issued_at: d.u64()?,
            expires_at: d.u64()?,
            server_key_id: d.u8()?,
            server_sig: d.item()?,
        })
    }
}

// ---------------------------------------------------------------- Visit

/// A restaurant from the map service.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Place {
    pub place_id: String,
    pub name: String,
    pub location: GeoPoint,
}

impl Place {
    fn encode_into(&self, e: &mut Enc) {
        e.text(&self.place_id).text(&self.name);
        self.location.encode_into(e);
    }
    fn decode_from(d: &mut Dec<'_>) -> Result<Self, Error> {
        Ok(Self {
            place_id: d.string()?,
            name: d.string()?,
            location: GeoPoint::decode_from(d)?,
        })
    }
}

/// The fields of a Visit that `visit_id` covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisitBody {
    pub user_id: UserId,
    pub place: Place,
    /// Hash of the food photo. Any photo can be used, including one from
    /// the gallery (Byung's decision, Oct 30).
    pub photo_hash: Hash,
    /// When the visit was collected in the app (not where: no location is
    /// recorded). The stamp and review windows count from here.
    pub taken_at: Time,
}

impl VisitBody {
    pub fn id(&self) -> Hash {
        tagged_hash(tag::VISIT_ID, 1, |e| {
            e.array(7).bytes(&self.user_id);
            self.place.encode_into(e);
            e.bytes(&self.photo_hash).u64(self.taken_at);
        })
    }
}

/// Our server's stamp, given after the device-integrity check. The server
/// only ever sees `visit_id`.
///
/// `server_key_id` is not in the spec's field list; it says which server key
/// made the stamp, the same way certificates do, so the key can be replaced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp {
    pub stamp_at: Time,
    pub server_key_id: u8,
    pub stamp_sig: Signature,
}

impl Stamp {
    pub fn signed_bytes(visit_id: &Hash, stamp_at: Time) -> Vec<u8> {
        signed_message(tag::STAMP, 2, |e| {
            e.bytes(visit_id).u64(stamp_at);
        })
    }

    /// Server side.
    pub fn issue(
        server: &dyn Signer,
        server_key_id: u8,
        visit_id: &Hash,
        stamp_at: Time,
    ) -> Result<Self, Error> {
        Ok(Self {
            stamp_at,
            server_key_id,
            stamp_sig: server.sign(&Self::signed_bytes(visit_id, stamp_at))?,
        })
    }
}

impl Cbor for Stamp {
    fn encode(&self, e: &mut Enc) {
        e.array(3)
            .u64(self.stamp_at)
            .u64(self.server_key_id as u64)
            .item(&self.stamp_sig);
    }
    fn decode(d: &mut Dec<'_>) -> Result<Self, Error> {
        d.expect_array(3)?;
        Ok(Self {
            stamp_at: d.u64()?,
            server_key_id: d.u8()?,
            stamp_sig: d.item()?,
        })
    }
}

/// The record made when you collect a restaurant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Visit {
    pub visit_id: Hash,
    pub body: VisitBody,
    /// The collector's device key over `visit_id`.
    pub user_sig: Signature,
    /// Empty until the server stamps it (the visit waits while offline).
    pub stamp: Option<Stamp>,
}

impl Visit {
    pub fn user_signed_bytes(visit_id: &Hash) -> Vec<u8> {
        signed_message(tag::VISIT, 1, |e| {
            e.bytes(visit_id);
        })
    }
}

impl Cbor for Visit {
    fn encode(&self, e: &mut Enc) {
        let b = &self.body;
        e.array(10).bytes(&self.visit_id).bytes(&b.user_id);
        b.place.encode_into(e);
        e.bytes(&b.photo_hash)
            .u64(b.taken_at)
            .item(&self.user_sig)
            .opt(&self.stamp);
    }
    fn decode(d: &mut Dec<'_>) -> Result<Self, Error> {
        d.expect_array(10)?;
        let visit_id = d.fixed()?;
        let user_id = d.fixed()?;
        let place = Place::decode_from(d)?;
        let photo_hash = d.fixed()?;
        let taken_at = d.u64()?;
        Ok(Self {
            visit_id,
            body: VisitBody {
                user_id,
                place,
                photo_hash,
                taken_at,
            },
            user_sig: d.item()?,
            stamp: d.opt()?,
        })
    }
}

// ---------------------------------------------------------------- Review

/// The fields of a Review that `review_id` covers. There is no rating.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewBody {
    pub reviewer: Certificate,
    pub visit: Visit,
    pub title: String,
    pub text: String,
    pub photo_hash: Option<Hash>,
    pub written_at: Time,
}

impl ReviewBody {
    pub fn id(&self) -> Hash {
        tagged_hash(tag::REVIEW_ID, 6, |e| {
            e.item(&self.reviewer)
                .item(&self.visit)
                .text(&self.title)
                .text(&self.text)
                .opt(&self.photo_hash)
                .u64(self.written_at);
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Review {
    pub review_id: Hash,
    pub body: ReviewBody,
    pub reviewer_sig: Signature,
}

impl Review {
    pub fn signed_bytes(review_id: &Hash) -> Vec<u8> {
        signed_message(tag::REVIEW, 1, |e| {
            e.bytes(review_id);
        })
    }

    pub fn place(&self) -> &Place {
        &self.body.visit.body.place
    }

    /// The list entry this review should be advertised with.
    pub fn list_entry(&self) -> ListEntry {
        let place = self.place();
        ListEntry {
            review_id: self.review_id,
            restaurant_id: place.place_id.clone(),
            restaurant_name: place.name.clone(),
            location: place.location,
            title: self.body.title.clone(),
            reviewer_id: self.body.reviewer.reviewer_id(),
            visit_date: self.body.visit.body.taken_at,
        }
    }
}

impl Cbor for Review {
    fn encode(&self, e: &mut Enc) {
        let b = &self.body;
        e.array(8)
            .bytes(&self.review_id)
            .item(&b.reviewer)
            .item(&b.visit)
            .text(&b.title)
            .text(&b.text)
            .opt(&b.photo_hash)
            .u64(b.written_at)
            .item(&self.reviewer_sig);
    }
    fn decode(d: &mut Dec<'_>) -> Result<Self, Error> {
        d.expect_array(8)?;
        Ok(Self {
            review_id: d.fixed()?,
            body: ReviewBody {
                reviewer: d.item()?,
                visit: d.item()?,
                title: d.string()?,
                text: d.string()?,
                photo_hash: d.opt()?,
                written_at: d.u64()?,
            },
            reviewer_sig: d.item()?,
        })
    }
}

// ---------------------------------------------------------------- Told-by note

/// How the review reached me: handoff count, who gave it to me, and when.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToldBy {
    /// Handoffs from the reviewer to me. 1 means the reviewer told me.
    pub told_count: u16,
    pub teller_id: UserId,
    pub teller_name: String,
    pub told_at: Time,
}

impl Cbor for ToldBy {
    fn encode(&self, e: &mut Enc) {
        e.array(4)
            .u64(self.told_count as u64)
            .bytes(&self.teller_id)
            .text(&self.teller_name)
            .u64(self.told_at);
    }
    fn decode(d: &mut Dec<'_>) -> Result<Self, Error> {
        d.expect_array(4)?;
        Ok(Self {
            told_count: d.u16()?,
            teller_id: d.fixed()?,
            teller_name: d.string()?,
            told_at: d.u64()?,
        })
    }
}

/// A review kept on this phone: one I wrote (`told` empty) or one I saved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavedReview {
    pub review: Review,
    pub photo: Option<Vec<u8>>,
    pub told: Option<ToldBy>,
    pub saved_at: Time,
}

impl SavedReview {
    /// The count I send with this review when someone opens it: 0 for my
    /// own review, otherwise the count in my note.
    pub fn sharer_told_count(&self) -> u16 {
        self.told.as_ref().map_or(0, |t| t.told_count)
    }

    pub fn is_own(&self) -> bool {
        self.told.is_none()
    }
}

impl Cbor for SavedReview {
    fn encode(&self, e: &mut Enc) {
        e.array(4)
            .item(&self.review)
            .opt_bytes(self.photo.as_deref())
            .opt(&self.told)
            .u64(self.saved_at);
    }
    fn decode(d: &mut Dec<'_>) -> Result<Self, Error> {
        d.expect_array(4)?;
        Ok(Self {
            review: d.item()?,
            photo: d.opt_bytes()?.map(<[u8]>::to_vec),
            told: d.opt()?,
            saved_at: d.u64()?,
        })
    }
}

// ---------------------------------------------------------------- Catalog

/// One line of a sharer's list, about 120 bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ListEntry {
    pub review_id: Hash,
    pub restaurant_id: String,
    pub restaurant_name: String,
    pub location: GeoPoint,
    pub title: String,
    pub reviewer_id: ReviewerId,
    /// `taken_at` of the reviewed visit.
    pub visit_date: Time,
}

impl Cbor for ListEntry {
    fn encode(&self, e: &mut Enc) {
        e.array(8)
            .bytes(&self.review_id)
            .text(&self.restaurant_id)
            .text(&self.restaurant_name);
        self.location.encode_into(e);
        e.text(&self.title)
            .bytes(&self.reviewer_id)
            .u64(self.visit_date);
    }
    fn decode(d: &mut Dec<'_>) -> Result<Self, Error> {
        d.expect_array(8)?;
        Ok(Self {
            review_id: d.fixed()?,
            restaurant_id: d.string()?,
            restaurant_name: d.string()?,
            location: GeoPoint::decode_from(d)?,
            title: d.string()?,
            reviewer_id: d.fixed()?,
            visit_date: d.u64()?,
        })
    }
}

/// Everything a phone shares: one entry per saved review, and a version
/// that goes up by 1 on every change.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Catalog {
    pub version: u32,
    pub entries: Vec<ListEntry>,
}

impl Cbor for Catalog {
    fn encode(&self, e: &mut Enc) {
        e.array(2).u64(self.version as u64).list(&self.entries);
    }
    fn decode(d: &mut Dec<'_>) -> Result<Self, Error> {
        d.expect_array(2)?;
        Ok(Self {
            version: d.u32()?,
            entries: d.list()?,
        })
    }
}

// ---------------------------------------------------------------- Cards and trades

/// A collected restaurant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Card {
    pub card_id: Hash,
    pub place: Place,
    /// The visit that created it.
    pub origin_visit: Hash,
    /// Empty until traded.
    pub history: Vec<TradeRecord>,
}

impl Card {
    pub fn id_for(origin_visit: &Hash) -> Hash {
        tagged_hash(tag::CARD_ID, 1, |e| {
            e.bytes(origin_visit);
        })
    }

    pub fn from_visit(visit: &Visit) -> Self {
        Self {
            card_id: Self::id_for(&visit.visit_id),
            place: visit.body.place.clone(),
            origin_visit: visit.visit_id,
            history: Vec::new(),
        }
    }
}

impl Cbor for Card {
    fn encode(&self, e: &mut Enc) {
        e.array(6).bytes(&self.card_id);
        self.place.encode_into(e);
        e.bytes(&self.origin_visit).list(&self.history);
    }
    fn decode(d: &mut Dec<'_>) -> Result<Self, Error> {
        d.expect_array(6)?;
        Ok(Self {
            card_id: d.fixed()?,
            place: Place::decode_from(d)?,
            origin_visit: d.fixed()?,
            history: d.list()?,
        })
    }
}

/// Proof that two people swapped cards at a meeting. `user_a` is the
/// smaller user id, so both phones build the same record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TradeRecord {
    pub meeting_id: MeetingId,
    pub user_a: UserId,
    pub user_b: UserId,
    pub card_a: Hash,
    pub card_b: Hash,
    pub at: Time,
    pub sig_a: Signature,
    pub sig_b: Signature,
}

impl TradeRecord {
    pub fn signed_bytes(
        meeting_id: &MeetingId,
        user_a: &UserId,
        user_b: &UserId,
        card_a: &Hash,
        card_b: &Hash,
        at: Time,
    ) -> Vec<u8> {
        signed_message(tag::TRADE, 6, |e| {
            e.bytes(meeting_id)
                .bytes(user_a)
                .bytes(user_b)
                .bytes(card_a)
                .bytes(card_b)
                .u64(at);
        })
    }
}

impl Cbor for TradeRecord {
    fn encode(&self, e: &mut Enc) {
        e.array(8)
            .bytes(&self.meeting_id)
            .bytes(&self.user_a)
            .bytes(&self.user_b)
            .bytes(&self.card_a)
            .bytes(&self.card_b)
            .u64(self.at)
            .item(&self.sig_a)
            .item(&self.sig_b);
    }
    fn decode(d: &mut Dec<'_>) -> Result<Self, Error> {
        d.expect_array(8)?;
        Ok(Self {
            meeting_id: d.fixed()?,
            user_a: d.fixed()?,
            user_b: d.fixed()?,
            card_a: d.fixed()?,
            card_b: d.fixed()?,
            at: d.u64()?,
            sig_a: d.item()?,
            sig_b: d.item()?,
        })
    }
}

// ---------------------------------------------------------------- Revocations

/// A device key that is no longer trusted from `since` on. Reviews written
/// before `since` stay valid (for example after moving to a new phone).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevokedKey {
    pub key: PublicKey,
    pub since: Time,
}

impl Cbor for RevokedKey {
    fn encode(&self, e: &mut Enc) {
        e.array(2).item(&self.key).u64(self.since);
    }
    fn decode(d: &mut Dec<'_>) -> Result<Self, Error> {
        d.expect_array(2)?;
        Ok(Self {
            key: d.item()?,
            since: d.u64()?,
        })
    }
}

/// The server-signed list of revoked people and keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationList {
    pub issued_at: Time,
    /// Every review by these people is rejected.
    pub users: Vec<UserId>,
    pub keys: Vec<RevokedKey>,
    pub server_key_id: u8,
    pub server_sig: Signature,
}

impl RevocationList {
    pub fn signed_bytes(&self) -> Vec<u8> {
        signed_message(tag::REVOCATIONS, 4, |e| {
            e.u64(self.issued_at);
            e.array(self.users.len());
            for u in &self.users {
                e.bytes(u);
            }
            e.list(&self.keys).u64(self.server_key_id as u64);
        })
    }

    /// Server side. Sorts the entries so the same set always signs the same.
    pub fn issue(
        server: &dyn Signer,
        server_key_id: u8,
        issued_at: Time,
        mut users: Vec<UserId>,
        mut keys: Vec<RevokedKey>,
    ) -> Result<Self, Error> {
        users.sort();
        users.dedup();
        keys.sort_by(|a, b| a.key.cmp(&b.key).then(a.since.cmp(&b.since)));
        keys.dedup_by(|a, b| a.key == b.key);
        let mut list = Self {
            issued_at,
            users,
            keys,
            server_key_id,
            server_sig: Signature([0; 64]),
        };
        list.server_sig = server.sign(&list.signed_bytes())?;
        Ok(list)
    }
}

impl Cbor for RevocationList {
    fn encode(&self, e: &mut Enc) {
        e.array(5).u64(self.issued_at).array(self.users.len());
        for u in &self.users {
            e.bytes(u);
        }
        e.list(&self.keys)
            .u64(self.server_key_id as u64)
            .item(&self.server_sig);
    }
    fn decode(d: &mut Dec<'_>) -> Result<Self, Error> {
        d.expect_array(5)?;
        let issued_at = d.u64()?;
        let n = d.array()?;
        let mut users = Vec::with_capacity(n);
        for _ in 0..n {
            users.push(d.fixed()?);
        }
        Ok(Self {
            issued_at,
            users,
            keys: d.list()?,
            server_key_id: d.u8()?,
            server_sig: d.item()?,
        })
    }
}
