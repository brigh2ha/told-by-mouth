//! Writing a review and checking one that arrives from someone else.

use crate::collect::verify_visit;
use crate::crypto::{sha256, Signer};
use crate::error::Error;
use crate::limits::{Time, CLOCK_DRIFT, PHOTO_MAX_BYTES, REVIEW_WINDOW, TEXT_MAX, TITLE_MAX};
use crate::model::{check_len, Certificate, ListEntry, Review, ReviewBody, Visit};
use crate::trust::Trust;

/// What the user typed.
#[derive(Clone, Debug, Default)]
pub struct Draft {
    pub title: String,
    pub text: String,
    pub photo: Option<Vec<u8>>,
}

pub fn check_text(title: &str, text: &str) -> Result<(), Error> {
    check_len("title", title, 1, TITLE_MAX)?;
    check_len("text", text, 1, TEXT_MAX)
}

fn check_written_in_window(visit: &Visit, written_at: Time) -> Result<(), Error> {
    let taken_at = visit.body.taken_at;
    if written_at + CLOCK_DRIFT < taken_at {
        return Err(Error::InFuture);
    }
    if written_at > taken_at + REVIEW_WINDOW {
        return Err(Error::VisitTooOld);
    }
    Ok(())
}

/// Runs every check, then builds the Review and has the secure chip sign
/// it. `already_reviewed` says whether this visit has a review already.
pub fn write_review(
    me: &Certificate,
    signer: &dyn Signer,
    trust: &Trust,
    visit: &Visit,
    already_reviewed: bool,
    draft: &Draft,
    now: Time,
) -> Result<Review, Error> {
    if visit.body.user_id != me.user_id || signer.public_key() != me.device_key {
        return Err(Error::NotMyVisit);
    }
    if visit.stamp.is_none() {
        return Err(Error::NotStamped);
    }
    check_written_in_window(visit, now)?;
    if already_reviewed {
        return Err(Error::AlreadyReviewed);
    }
    trust.check_certificate_at(me, now).map_err(|e| match e {
        Error::CertificateNotValid => Error::CertificateExpired,
        e => e,
    })?;
    check_text(&draft.title, &draft.text)?;
    let photo_hash = match &draft.photo {
        Some(p) if p.len() > PHOTO_MAX_BYTES => {
            return Err(Error::PhotoTooLarge {
                max: PHOTO_MAX_BYTES,
            })
        }
        Some(p) => Some(sha256(p)),
        None => None,
    };
    let body = ReviewBody {
        reviewer: me.clone(),
        visit: visit.clone(),
        title: draft.title.clone(),
        text: draft.text.clone(),
        photo_hash,
        written_at: now,
    };
    let review_id = body.id();
    let reviewer_sig = signer.sign(&Review::signed_bytes(&review_id))?;
    Ok(Review {
        review_id,
        body,
        reviewer_sig,
    })
}

/// Every check a receiver runs on a full review (spec section 8).
pub fn verify_review(
    review: &Review,
    photo: Option<&[u8]>,
    trust: &Trust,
    now: Time,
) -> Result<(), Error> {
    let b = &review.body;
    // The id matches the contents, and the photo matches its hash.
    if b.id() != review.review_id {
        return Err(Error::IdMismatch("review"));
    }
    match (photo, &b.photo_hash) {
        (None, _) => {}
        (Some(p), Some(h)) if p.len() <= PHOTO_MAX_BYTES && sha256(p) == *h => {}
        (Some(p), _) if p.len() > PHOTO_MAX_BYTES => {
            return Err(Error::PhotoTooLarge {
                max: PHOTO_MAX_BYTES,
            })
        }
        (Some(_), _) => return Err(Error::PhotoMismatch),
    }
    if b.written_at > now + CLOCK_DRIFT {
        return Err(Error::InFuture);
    }
    // The certificate was valid at written_at and isn't revoked; the
    // reviewer's signature is valid.
    trust.check_certificate_at(&b.reviewer, b.written_at)?;
    b.reviewer.device_key.verify(
        &Review::signed_bytes(&review.review_id),
        &review.reviewer_sig,
        "review",
    )?;
    // The visit belongs to the reviewer, is signed and stamped in time, and
    // the review was written within 30 days of it.
    if b.visit.body.user_id != b.reviewer.user_id {
        return Err(Error::NotMyVisit);
    }
    verify_visit(&b.visit, &b.reviewer.device_key, trust)?;
    check_written_in_window(&b.visit, b.written_at)?;
    check_text(&b.title, &b.text)
}

/// The list entry told the truth: same title, restaurant, location, visit
/// date and reviewer.
pub fn check_entry(entry: &ListEntry, review: &Review) -> Result<(), Error> {
    let real = review.list_entry();
    let field = if entry.review_id != real.review_id {
        "review id"
    } else if entry.title != real.title {
        "title"
    } else if entry.restaurant_id != real.restaurant_id
        || entry.restaurant_name != real.restaurant_name
    {
        "restaurant"
    } else if entry.location != real.location {
        "location"
    } else if entry.visit_date != real.visit_date {
        "visit date"
    } else if entry.reviewer_id != real.reviewer_id {
        "reviewer"
    } else {
        return Ok(());
    };
    Err(Error::EntryMismatch(field))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Signature;
    use crate::limits::{DAY, HOUR};
    use crate::testkit::*;

    #[test]
    fn write_rules() {
        let w = World::new();
        let kim = w.person("Kim Minji");
        let visit = kim.visit(&w, gangnam(), T0);
        let draft = draft("Best cold noodles", "Broth like ice, noodles like silk.");

        // Fine within the window.
        let r = write_review(
            &kim.cert,
            &kim.key,
            &w.trust,
            &visit,
            false,
            &draft,
            T0 + DAY,
        )
        .unwrap();
        verify_review(&r, None, &w.trust, T0 + DAY).unwrap();

        // One review per visit.
        assert_eq!(
            write_review(
                &kim.cert,
                &kim.key,
                &w.trust,
                &visit,
                true,
                &draft,
                T0 + DAY
            )
            .unwrap_err(),
            Error::AlreadyReviewed
        );
        // Older than 30 days.
        assert_eq!(
            write_review(
                &kim.cert,
                &kim.key,
                &w.trust,
                &visit,
                false,
                &draft,
                T0 + 31 * DAY
            )
            .unwrap_err(),
            Error::VisitTooOld
        );
        // Not stamped.
        let mut unstamped = visit.clone();
        unstamped.stamp = None;
        assert_eq!(
            write_review(
                &kim.cert,
                &kim.key,
                &w.trust,
                &unstamped,
                false,
                &draft,
                T0 + HOUR
            )
            .unwrap_err(),
            Error::NotStamped
        );
        // Someone else's visit (for example a traded card) does not count.
        let lee = w.person("Lee Jiwoo");
        assert_eq!(
            write_review(
                &lee.cert,
                &lee.key,
                &w.trust,
                &visit,
                false,
                &draft,
                T0 + HOUR
            )
            .unwrap_err(),
            Error::NotMyVisit
        );
        // Text limits.
        for (t, x) in [("", "x"), ("x", ""), (&"가".repeat(41)[..], "x")] {
            assert!(matches!(
                write_review(
                    &kim.cert,
                    &kim.key,
                    &w.trust,
                    &visit,
                    false,
                    &self::draft(t, x),
                    T0 + HOUR
                ),
                Err(Error::Length { .. })
            ));
        }
        let long = "가".repeat(1000);
        write_review(
            &kim.cert,
            &kim.key,
            &w.trust,
            &visit,
            false,
            &self::draft(&"가".repeat(40), &long),
            T0 + HOUR,
        )
        .unwrap();
        // Expired certificate.
        let old = w.person_at("Old Timer", T0 - 400 * DAY);
        let old_visit = old.visit(&w, gangnam(), T0);
        assert_eq!(
            write_review(
                &old.cert,
                &old.key,
                &w.trust,
                &old_visit,
                false,
                &draft,
                T0 + HOUR
            )
            .unwrap_err(),
            Error::CertificateExpired
        );
    }

    #[test]
    fn tampering_is_caught() {
        let w = World::new();
        let kim = w.person("Kim Minji");
        let photo = vec![7u8; 5000];
        let r = kim.review(&w, gangnam(), T0, "Best cold noodles", Some(photo.clone()));
        let now = T0 + DAY;
        verify_review(&r, Some(&photo), &w.trust, now).unwrap();

        let mut edited = r.clone();
        edited.body.text.push('!');
        assert_eq!(
            verify_review(&edited, None, &w.trust, now),
            Err(Error::IdMismatch("review"))
        );

        // Re-hashing after an edit still fails the signature.
        edited.review_id = edited.body.id();
        assert_eq!(
            verify_review(&edited, None, &w.trust, now),
            Err(Error::BadSignature("review"))
        );

        let mut bad_sig = r.clone();
        bad_sig.reviewer_sig = Signature([1; 64]);
        assert!(verify_review(&bad_sig, None, &w.trust, now).is_err());

        assert_eq!(
            verify_review(&r, Some(&[1, 2, 3]), &w.trust, now),
            Err(Error::PhotoMismatch)
        );

        // Moving the visit's restaurant breaks the visit id (and the review id).
        let mut moved = r.clone();
        moved.body.visit.body.place.location.lat += 1000;
        moved.review_id = moved.body.id();
        assert!(verify_review(&moved, None, &w.trust, now).is_err());

        // Claiming someone else's visit fails.
        let lee = w.person("Lee Jiwoo");
        let lee_visit = lee.visit(&w, gangnam(), T0);
        let mut stolen = r.clone();
        stolen.body.visit = lee_visit;
        stolen.review_id = stolen.body.id();
        stolen.reviewer_sig = kim
            .key
            .sign(&Review::signed_bytes(&stolen.review_id))
            .unwrap();
        assert_eq!(
            verify_review(&stolen, None, &w.trust, now),
            Err(Error::NotMyVisit)
        );

        // Written in the future.
        assert_eq!(
            verify_review(&r, None, &w.trust, T0 - DAY),
            Err(Error::InFuture)
        );
    }

    #[test]
    fn expired_later_is_still_valid_but_revoked_is_not() {
        let w = World::new();
        let kim = w.person("Kim Minji");
        let r = kim.review(&w, gangnam(), T0, "Good", None);
        // Two years later the certificate has expired, but checks use written_at.
        verify_review(&r, None, &w.trust, T0 + 730 * DAY).unwrap();

        let mut trust = w.trust.clone();
        trust
            .update_revocations(w.revoke_users(&[kim.cert.user_id], T0 + 2 * DAY))
            .unwrap();
        assert_eq!(
            verify_review(&r, None, &trust, T0 + 3 * DAY),
            Err(Error::Revoked)
        );
    }

    #[test]
    fn entry_must_match() {
        let w = World::new();
        let kim = w.person("Kim Minji");
        let r = kim.review(&w, gangnam(), T0, "Good", None);
        let e = r.list_entry();
        check_entry(&e, &r).unwrap();
        let mut newer = e.clone();
        newer.visit_date += DAY;
        assert_eq!(
            check_entry(&newer, &r),
            Err(Error::EntryMismatch("visit date"))
        );
        let mut title = e.clone();
        title.title = "Amazing!!!".into();
        assert_eq!(check_entry(&title, &r), Err(Error::EntryMismatch("title")));
        let mut closer = e;
        closer.location.lat += 5000;
        assert_eq!(
            check_entry(&closer, &r),
            Err(Error::EntryMismatch("location"))
        );
    }
}
