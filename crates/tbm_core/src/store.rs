//! What the phone keeps (spec "What the phone stores"). The apps persist it
//! as one CBOR blob; nothing from a meeting is kept except what I save.

use std::collections::{BTreeMap, BTreeSet};

use crate::cbor::{Cbor, Dec, Enc};
use crate::crypto::Hash;
use crate::error::Error;
use crate::limits::{Time, SAVED_LIMIT};
use crate::model::{Card, Catalog, Certificate, ReviewerId, SavedReview, UserId, Visit};
use crate::trust::Trust;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Store {
    /// My certificate. The key itself stays in the secure chip.
    pub identity: Option<Certificate>,
    /// My visits, stamped or waiting for a stamp. Full-size photos stay in
    /// the app's files, keyed by photo_hash.
    pub(crate) visits: BTreeMap<Hash, Visit>,
    /// My cards, by card_id.
    pub(crate) cards: BTreeMap<Hash, Card>,
    /// My own reviews and the ones I saved, by review_id.
    pub(crate) saved: BTreeMap<Hash, SavedReview>,
    /// Visits that have had a review (kept even if the review is deleted).
    pub(crate) reviewed_visits: BTreeSet<Hash>,
    pub(crate) blocked_users: BTreeSet<UserId>,
    pub(crate) blocked_reviewers: BTreeSet<ReviewerId>,
    /// Range filter in metres; `None` is "any" (the default).
    pub range_m: Option<u32>,
    pub(crate) catalog_version: u32,
}

impl Store {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn visits(&self) -> impl Iterator<Item = &Visit> {
        self.visits.values()
    }

    pub fn visit(&self, visit_id: &Hash) -> Option<&Visit> {
        self.visits.get(visit_id)
    }

    pub fn cards(&self) -> impl Iterator<Item = &Card> {
        self.cards.values()
    }

    pub fn card(&self, card_id: &Hash) -> Option<&Card> {
        self.cards.get(card_id)
    }

    pub fn saved(&self) -> impl Iterator<Item = &SavedReview> {
        self.saved.values()
    }

    pub fn saved_review(&self, review_id: &Hash) -> Option<&SavedReview> {
        self.saved.get(review_id)
    }

    pub fn saved_ids(&self) -> BTreeSet<Hash> {
        self.saved.keys().copied().collect()
    }

    pub fn is_reviewed(&self, visit_id: &Hash) -> bool {
        self.reviewed_visits.contains(visit_id)
    }

    pub fn blocked_users(&self) -> &BTreeSet<UserId> {
        &self.blocked_users
    }

    pub fn blocked_reviewers(&self) -> &BTreeSet<ReviewerId> {
        &self.blocked_reviewers
    }

    pub fn catalog_version(&self) -> u32 {
        self.catalog_version
    }

    fn bump(&mut self) {
        self.catalog_version = self.catalog_version.wrapping_add(1);
    }

    /// Reviews saved from others; my own do not count toward the limit.
    pub fn saved_from_others(&self) -> usize {
        self.saved.values().filter(|s| !s.is_own()).count()
    }

    /// The list I share: one entry per saved review, ordered by review_id.
    pub fn catalog(&self) -> Catalog {
        Catalog {
            version: self.catalog_version,
            entries: self.saved.values().map(|s| s.review.list_entry()).collect(),
        }
    }

    pub(crate) fn put_saved(&mut self, saved: SavedReview) -> Result<(), Error> {
        if !saved.is_own() && self.saved_from_others() >= SAVED_LIMIT {
            return Err(Error::SavedLimitReached);
        }
        if saved.is_own() {
            self.reviewed_visits
                .insert(saved.review.body.visit.visit_id);
        }
        self.saved.insert(saved.review.review_id, saved);
        self.bump();
        Ok(())
    }

    /// Deletes a saved review: it leaves storage and the catalog.
    pub fn delete_saved(&mut self, review_id: &Hash) -> bool {
        let removed = self.saved.remove(review_id).is_some();
        if removed {
            self.bump();
        }
        removed
    }

    /// Drops saved reviews whose reviewer is now revoked. Returns how many.
    pub fn drop_revoked(&mut self, trust: &Trust) -> usize {
        let before = self.saved.len();
        self.saved
            .retain(|_, s| !trust.is_revoked(&s.review.body.reviewer, s.review.body.written_at));
        let dropped = before - self.saved.len();
        if dropped > 0 {
            self.bump();
        }
        dropped
    }

    pub fn block(&mut self, user: UserId, reviewer_ids: impl IntoIterator<Item = ReviewerId>) {
        self.blocked_users.insert(user);
        self.blocked_reviewers.extend(reviewer_ids);
    }

    pub fn unblock(&mut self, user: &UserId, reviewer_ids: impl IntoIterator<Item = ReviewerId>) {
        self.blocked_users.remove(user);
        for r in reviewer_ids {
            self.blocked_reviewers.remove(&r);
        }
    }
}

impl Cbor for Store {
    fn encode(&self, e: &mut Enc) {
        e.array(10).u64(1).opt(&self.identity);
        e.array(self.visits.len());
        for v in self.visits.values() {
            e.item(v);
        }
        e.array(self.cards.len());
        for c in self.cards.values() {
            e.item(c);
        }
        e.array(self.saved.len());
        for s in self.saved.values() {
            e.item(s);
        }
        e.array(self.reviewed_visits.len());
        for v in &self.reviewed_visits {
            e.bytes(v);
        }
        e.array(self.blocked_users.len());
        for u in &self.blocked_users {
            e.bytes(u);
        }
        e.array(self.blocked_reviewers.len());
        for r in &self.blocked_reviewers {
            e.bytes(r);
        }
        match self.range_m {
            Some(r) => e.u64(r as u64),
            None => e.null(),
        };
        e.u64(self.catalog_version as u64);
    }

    fn decode(d: &mut Dec<'_>) -> Result<Self, Error> {
        d.expect_array(10)?;
        if d.u64()? != 1 {
            return Err(Error::Decode("unknown store version".into()));
        }
        let identity = d.opt()?;
        let visits = d
            .list::<Visit>()?
            .into_iter()
            .map(|v| (v.visit_id, v))
            .collect();
        let cards = d
            .list::<Card>()?
            .into_iter()
            .map(|c| (c.card_id, c))
            .collect();
        let saved = d
            .list::<SavedReview>()?
            .into_iter()
            .map(|s| (s.review.review_id, s))
            .collect();
        let reviewed_visits = d.list::<Hash>()?.into_iter().collect();
        let blocked_users = d.list::<UserId>()?.into_iter().collect();
        let blocked_reviewers = d.list::<ReviewerId>()?.into_iter().collect();
        let range_m = if d.null()? { None } else { Some(d.u32()?) };
        Ok(Self {
            identity,
            visits,
            cards,
            saved,
            reviewed_visits,
            blocked_users,
            blocked_reviewers,
            range_m,
            catalog_version: d.u32()?,
        })
    }
}

/// Saved-at helper used by the node.
pub(crate) fn own_saved(
    review: crate::model::Review,
    photo: Option<Vec<u8>>,
    now: Time,
) -> SavedReview {
    SavedReview {
        review,
        photo,
        told: None,
        saved_at: now,
    }
}
