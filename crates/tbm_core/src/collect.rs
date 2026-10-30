//! Collecting a restaurant: building and signing the Visit, and accepting
//! the server's stamp.
//!
//! There is no location check (Byung's decision, Oct 30): the app trusts
//! the reviewer, whose real name stands behind every review. The phone's
//! location fix is still recorded in the Visit, but nothing is refused
//! because of it.

use crate::crypto::{Hash, PublicKey, Signer};
use crate::error::Error;
use crate::limits::{PLACE_ID_MAX_BYTES, PLACE_NAME_MAX};
use crate::model::{check_len, Fix, Place, Stamp, UserId, Visit, VisitBody};
use crate::trust::Trust;

/// The fix only has to be a valid coordinate; its accuracy and distance
/// from the restaurant are not checked.
pub fn check_fix(fix: &Fix) -> Result<(), Error> {
    fix.location.check()
}

pub fn check_place(place: &Place) -> Result<(), Error> {
    if place.place_id.is_empty() || place.place_id.len() > PLACE_ID_MAX_BYTES {
        return Err(Error::Length {
            field: "place id",
            min: 1,
            max: PLACE_ID_MAX_BYTES,
        });
    }
    check_len("restaurant name", &place.name, 1, PLACE_NAME_MAX)?;
    place.location.check()
}

/// Builds the Visit for an in-app photo and has the secure chip sign it.
/// The visit still needs the server stamp before it becomes a Card.
pub fn new_visit(
    signer: &dyn Signer,
    user_id: UserId,
    place: Place,
    photo_hash: Hash,
    fix: Fix,
) -> Result<Visit, Error> {
    check_fix(&fix)?;
    check_place(&place)?;
    let body = VisitBody {
        user_id,
        place,
        photo_hash,
        fix,
    };
    let visit_id = body.id();
    let user_sig = signer.sign(&Visit::user_signed_bytes(&visit_id))?;
    Ok(Visit {
        visit_id,
        body,
        user_sig,
        stamp: None,
    })
}

/// Accepts the server's stamp onto a visit after checking it.
pub fn apply_stamp(visit: &mut Visit, stamp: Stamp, trust: &Trust) -> Result<(), Error> {
    trust.verify_stamp(&visit.visit_id, visit.body.fix.taken_at, &stamp)?;
    visit.stamp = Some(stamp);
    Ok(())
}

/// Every check on a visit someone else shows us: id, collector signature,
/// well-formed fields and the stamp.
pub fn verify_visit(visit: &Visit, collector_key: &PublicKey, trust: &Trust) -> Result<(), Error> {
    if visit.body.id() != visit.visit_id {
        return Err(Error::IdMismatch("visit"));
    }
    collector_key.verify(
        &Visit::user_signed_bytes(&visit.visit_id),
        &visit.user_sig,
        "visit",
    )?;
    check_fix(&visit.body.fix)?;
    check_place(&visit.body.place)?;
    let stamp = visit.stamp.as_ref().ok_or(Error::NotStamped)?;
    trust.verify_stamp(&visit.visit_id, visit.body.fix.taken_at, stamp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SoftwareSigner;
    use crate::geo::GeoPoint;
    use crate::limits::HOUR;

    const T0: u64 = 1_790_000_000;

    fn place() -> Place {
        Place {
            place_id: "kakao:123".into(),
            name: "Gangnam Noodle House".into(),
            location: GeoPoint::new(37_497_942, 127_027_621).unwrap(),
        }
    }

    fn fix(accuracy_m: u32, dlat: i32) -> Fix {
        Fix {
            taken_at: T0,
            location: GeoPoint::new(37_497_942 + dlat, 127_027_621).unwrap(),
            accuracy_m,
        }
    }

    #[test]
    fn no_location_check() {
        let device = SoftwareSigner::generate();
        // A coarse fix far from the restaurant is accepted: we trust the reviewer.
        new_visit(&device, [1; 16], place(), [2; 32], fix(5_000, 900_000)).unwrap();
        new_visit(&device, [1; 16], place(), [2; 32], fix(10, 0)).unwrap();
        // Coordinates must still be real ones.
        let mut bad = fix(10, 0);
        bad.location.lat = 91_000_000;
        assert_eq!(
            new_visit(&device, [1; 16], place(), [2; 32], bad).unwrap_err(),
            Error::BadLocation
        );
    }

    #[test]
    fn stamp_window() {
        let server = SoftwareSigner::generate();
        let trust = Trust::new([(1, server.public_key())]);
        let device = SoftwareSigner::generate();
        let mut visit = new_visit(&device, [1; 16], place(), [2; 32], fix(10, 0)).unwrap();
        assert_eq!(
            verify_visit(&visit, &device.public_key(), &trust),
            Err(Error::NotStamped)
        );

        let late = Stamp::issue(&server, 1, &visit.visit_id, T0 + 25 * HOUR).unwrap();
        assert_eq!(
            apply_stamp(&mut visit, late, &trust),
            Err(Error::StampTooLate)
        );
        let wrong_visit = Stamp::issue(&server, 1, &[0; 32], T0 + HOUR).unwrap();
        assert!(apply_stamp(&mut visit, wrong_visit, &trust).is_err());

        let ok = Stamp::issue(&server, 1, &visit.visit_id, T0 + HOUR).unwrap();
        apply_stamp(&mut visit, ok, &trust).unwrap();
        verify_visit(&visit, &device.public_key(), &trust).unwrap();

        // Someone else's key cannot claim this visit.
        let other = SoftwareSigner::generate();
        assert!(verify_visit(&visit, &other.public_key(), &trust).is_err());

        // Changing the place breaks the id.
        let mut moved = visit.clone();
        moved.body.place.location.lat += 10;
        assert_eq!(
            verify_visit(&moved, &device.public_key(), &trust),
            Err(Error::IdMismatch("visit"))
        );
    }
}
