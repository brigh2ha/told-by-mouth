//! Helpers for tests and simulations: a fake identity server with a
//! software key, people with software "secure chips", and ready-made visits
//! and reviews. Compiled only for tests or with the `testkit` feature.

use std::sync::Arc;

use crate::collect::{apply_stamp, new_visit};
use crate::crypto::{sha256, Signer, SoftwareSigner};
use crate::geo::GeoPoint;
use crate::limits::{Time, HOUR, MINUTE};
use crate::model::{
    Certificate, Fix, Place, Review, RevocationList, RevokedKey, Stamp, UserId, Visit,
};
use crate::review::{write_review, Draft};
use crate::trust::Trust;

/// 2026-09-21, a fixed "now" for tests.
pub const T0: Time = 1_790_000_000;
pub const SERVER_KEY_ID: u8 = 1;

/// Our identity server, in miniature.
pub struct World {
    pub server: SoftwareSigner,
    pub trust: Trust,
}

impl Default for World {
    fn default() -> Self {
        Self::new()
    }
}

impl World {
    pub fn new() -> Self {
        let server = SoftwareSigner::generate();
        let trust = Trust::new([(SERVER_KEY_ID, server.public_key())]);
        Self { server, trust }
    }

    /// A person whose certificate was issued 100 days before T0.
    pub fn person(&self, name: &str) -> Person {
        self.person_at(name, T0 - 100 * 24 * HOUR)
    }

    pub fn person_at(&self, name: &str, issued_at: Time) -> Person {
        let key = Arc::new(SoftwareSigner::generate());
        let user_id = user_id_for(name);
        let cert = Certificate::issue(
            &self.server,
            SERVER_KEY_ID,
            user_id,
            name,
            key.public_key(),
            issued_at,
        )
        .unwrap();
        Person { cert, key }
    }

    pub fn stamp(&self, visit_id: &[u8; 32], at: Time) -> Stamp {
        Stamp::issue(&self.server, SERVER_KEY_ID, visit_id, at).unwrap()
    }

    pub fn revoke_users(&self, users: &[UserId], issued_at: Time) -> RevocationList {
        RevocationList::issue(
            &self.server,
            SERVER_KEY_ID,
            issued_at,
            users.to_vec(),
            vec![],
        )
        .unwrap()
    }

    pub fn revoke_keys(&self, keys: &[RevokedKey], issued_at: Time) -> RevocationList {
        RevocationList::issue(
            &self.server,
            SERVER_KEY_ID,
            issued_at,
            vec![],
            keys.to_vec(),
        )
        .unwrap()
    }
}

/// A stable user id derived from the name, so tests are readable.
pub fn user_id_for(name: &str) -> UserId {
    sha256(name.as_bytes())[..16].try_into().unwrap()
}

pub struct Person {
    pub cert: Certificate,
    pub key: Arc<SoftwareSigner>,
}

impl Person {
    pub fn user_id(&self) -> UserId {
        self.cert.user_id
    }

    /// A stamped visit to `place`, photo taken at `taken_at` right there.
    pub fn visit(&self, w: &World, place: Place, taken_at: Time) -> Visit {
        let fix = Fix {
            taken_at,
            location: place.location,
            accuracy_m: 10,
        };
        let photo_hash =
            sha256(format!("{}{}{taken_at}", self.cert.real_name, place.place_id).as_bytes());
        let mut v = new_visit(&*self.key, self.cert.user_id, place, photo_hash, fix).unwrap();
        let stamp = w.stamp(&v.visit_id, taken_at + 5 * MINUTE);
        apply_stamp(&mut v, stamp, &w.trust).unwrap();
        v
    }

    /// Visits `place` at `taken_at` and writes a review an hour later.
    pub fn review(
        &self,
        w: &World,
        place: Place,
        taken_at: Time,
        title: &str,
        photo: Option<Vec<u8>>,
    ) -> Review {
        let visit = self.visit(w, place, taken_at);
        let d = Draft {
            title: title.into(),
            text: format!("{title}. Written by {}.", self.cert.real_name),
            photo,
        };
        write_review(
            &self.cert,
            &*self.key,
            &w.trust,
            &visit,
            false,
            &d,
            taken_at + HOUR,
        )
        .unwrap()
    }
}

pub fn draft(title: &str, text: &str) -> Draft {
    Draft {
        title: title.into(),
        text: text.into(),
        photo: None,
    }
}

pub fn place(id: &str, name: &str, lat: f64, lon: f64) -> Place {
    Place {
        place_id: id.into(),
        name: name.into(),
        location: GeoPoint::from_degrees(lat, lon).unwrap(),
    }
}

/// Gangnam Noodle House, the restaurant from the spec's worked example.
pub fn gangnam() -> Place {
    place(
        "kakao:1001",
        "Gangnam Noodle House",
        37.497_942,
        127.027_621,
    )
}

/// A café about 1.2 km from Gangnam Noodle House.
pub fn cafe_spot() -> GeoPoint {
    GeoPoint::from_degrees(37.508_742, 127.027_621).unwrap()
}
