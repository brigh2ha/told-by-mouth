//! Building the receiver's list from everyone nearby ("Building the list,
//! step by step" in the spec). The screens only draw the rows this returns.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::cbor::Cbor;
use crate::crypto::Hash;
use crate::geo::GeoPoint;
use crate::limits::{MAX_PER_RESTAURANT, PLACE_ID_MAX_BYTES, PLACE_NAME_MAX, TITLE_MAX};
use crate::model::{check_len, ListEntry, ReviewerId, UserId};

/// One nearby person's list, after their certificate was checked.
#[derive(Clone, Copy, Debug)]
pub struct Offer<'a> {
    pub holder: UserId,
    pub entries: &'a [ListEntry],
}

/// My side of the inputs.
#[derive(Clone, Copy, Debug)]
pub struct ListInputs<'a> {
    /// My location, if the phone has a fix.
    pub location: Option<GeoPoint>,
    /// Range filter in metres; `None` means any distance (the default).
    pub range_m: Option<u32>,
    pub saved: &'a BTreeSet<Hash>,
    pub blocked_users: &'a BTreeSet<UserId>,
    pub blocked_reviewers: &'a BTreeSet<ReviewerId>,
}

/// One line of the list.
#[derive(Clone, Debug, PartialEq)]
pub struct ListRow {
    pub entry: ListEntry,
    /// Everyone nearby who offered this review, so a tap can ask another
    /// holder if the first has left. Sorted.
    pub holders: Vec<UserId>,
    /// Straight-line distance from me to the restaurant, if I have a fix.
    pub distance_m: Option<f64>,
}

/// An entry that is obviously malformed is dropped before anything else.
fn well_formed(e: &ListEntry) -> bool {
    check_len("title", &e.title, 1, TITLE_MAX).is_ok()
        && check_len("restaurant name", &e.restaurant_name, 1, PLACE_NAME_MAX).is_ok()
        && !e.restaurant_id.is_empty()
        && e.restaurant_id.len() <= PLACE_ID_MAX_BYTES
        && e.location.check().is_ok()
}

/// Newer visit first, then smaller review_id. The last rule only breaks
/// exact ties, so every phone ranks the same way.
fn rank(a: &ListRow, b: &ListRow) -> Ordering {
    b.entry
        .visit_date
        .cmp(&a.entry.visit_date)
        .then_with(|| a.entry.review_id.cmp(&b.entry.review_id))
}

/// Differing claims about one review, keyed so the lowest-ranking claim
/// (oldest visit date) comes first, each with the holders who made it.
type Claims = BTreeMap<(u64, Vec<u8>), (ListEntry, Vec<UserId>)>;

pub fn build_list(offers: &[Offer<'_>], me: &ListInputs<'_>) -> Vec<ListRow> {
    // 1. Collect, dropping blocked sharers and blocked reviewers.
    // 2. Merge by review_id, keeping every holder. If sharers disagree about
    //    an entry, at most one of them tells the truth; keep the claim that
    //    ranks lowest (oldest visit date) so a lie can never jump the queue,
    //    and keep only the holders who made that claim. A tap then checks it.
    let mut claims: HashMap<Hash, Claims> = HashMap::new();
    for offer in offers {
        if me.blocked_users.contains(&offer.holder) {
            continue;
        }
        for e in offer.entries {
            if me.blocked_reviewers.contains(&e.reviewer_id) || !well_formed(e) {
                continue;
            }
            let (_, holders) = claims
                .entry(e.review_id)
                .or_default()
                .entry((e.visit_date, e.to_cbor()))
                .or_insert_with(|| (e.clone(), Vec::new()));
            holders.push(offer.holder);
        }
    }

    let mut groups: BTreeMap<String, Vec<ListRow>> = BTreeMap::new();
    for (review_id, variants) in claims {
        // 3. Hide saved. Saved reviews never count toward the cap.
        if me.saved.contains(&review_id) {
            continue;
        }
        let (_, (entry, mut holders)) = variants.into_iter().next().expect("non-empty");
        holders.sort();
        holders.dedup();
        // 4. Distance and the optional range filter (skipped without a fix).
        let distance_m = me.location.map(|here| here.distance_m(&entry.location));
        if let (Some(d), Some(range)) = (distance_m, me.range_m) {
            if d > range as f64 {
                continue;
            }
        }
        // 5. Group by restaurant.
        groups
            .entry(entry.restaurant_id.clone())
            .or_default()
            .push(ListRow {
                entry,
                holders,
                distance_m,
            });
    }

    let mut ordered: Vec<(Option<f64>, Vec<ListRow>)> = Vec::with_capacity(groups.len());
    for (_, mut rows) in groups {
        // 6. One per reviewer: their newest visit.
        rows.sort_by(rank);
        let mut seen = HashSet::new();
        rows.retain(|r| seen.insert(r.entry.reviewer_id));
        // 7 and 8. Already ranked; keep the top 3.
        rows.truncate(MAX_PER_RESTAURANT);
        let distance = rows
            .iter()
            .filter_map(|r| r.distance_m)
            .min_by(|a, b| a.total_cmp(b));
        ordered.push((distance, rows));
    }

    // 9. Nearest restaurant first; by name without a fix. Reviews of one
    //    restaurant stay together in rank order.
    ordered.sort_by(|(da, ra), (db, rb)| {
        let (a, b) = (&ra[0].entry, &rb[0].entry);
        let by_name = a
            .restaurant_name
            .cmp(&b.restaurant_name)
            .then_with(|| a.restaurant_id.cmp(&b.restaurant_id));
        match (da, db) {
            (Some(x), Some(y)) => x.total_cmp(y).then(by_name),
            _ => by_name,
        }
    });
    ordered.into_iter().flat_map(|(_, rows)| rows).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::DAY;
    use crate::testkit::{cafe_spot, gangnam, place, user_id_for};

    /// Days since 1970 for October 2026 dates in the worked example.
    fn oct(day: u64) -> u64 {
        // 2026-10-01 00:00 UTC
        1_790_812_800 + (day - 1) * DAY
    }

    fn entry(id: u8, reviewer: &str, visit_date: u64) -> ListEntry {
        let p = gangnam();
        ListEntry {
            review_id: [id; 32],
            restaurant_id: p.place_id,
            restaurant_name: p.name,
            location: p.location,
            title: format!("Review {}", id as char),
            reviewer_id: user_id_for(reviewer)[..8].try_into().unwrap(),
            visit_date,
        }
    }

    struct Fixture {
        saved: BTreeSet<Hash>,
        blocked_users: BTreeSet<UserId>,
        blocked_reviewers: BTreeSet<ReviewerId>,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                saved: BTreeSet::new(),
                blocked_users: BTreeSet::new(),
                blocked_reviewers: BTreeSet::new(),
            }
        }
        fn inputs(&self, location: Option<GeoPoint>, range_m: Option<u32>) -> ListInputs<'_> {
            ListInputs {
                location,
                range_m,
                saved: &self.saved,
                blocked_users: &self.blocked_users,
                blocked_reviewers: &self.blocked_reviewers,
            }
        }
    }

    fn ids(rows: &[ListRow]) -> String {
        rows.iter().map(|r| r.entry.review_id[0] as char).collect()
    }

    #[test]
    fn worked_example_from_the_spec() {
        let a = entry(b'A', "Kim", oct(28));
        let b = entry(b'B', "Kim", oct(10));
        let c = entry(b'C', "Lee", oct(29));
        let d = entry(b'D', "Park", oct(2) - 29 * DAY); // Sep 2
        let e = entry(b'E', "Choi", oct(20));
        let kim = [a.clone(), b.clone()];
        let lee = [c.clone()];
        let park = [d.clone()];
        let choi = [e.clone()];
        let f = Fixture::new();
        let bo = f.inputs(Some(cafe_spot()), None);

        let offers = [
            Offer {
                holder: user_id_for("Kim"),
                entries: &kim,
            },
            Offer {
                holder: user_id_for("Lee"),
                entries: &lee,
            },
            Offer {
                holder: user_id_for("Park"),
                entries: &park,
            },
            Offer {
                holder: user_id_for("Choi"),
                entries: &choi,
            },
        ];
        let rows = build_list(&offers, &bo);
        assert_eq!(ids(&rows), "CAE");
        let km = rows[0].distance_m.unwrap();
        assert!((1_150.0..1_250.0).contains(&km), "{km}");

        // Lee walks away and nobody else holds C: D moves up.
        let rows = build_list(&[offers[0], offers[2], offers[3]], &bo);
        assert_eq!(ids(&rows), "AED");

        // If Kim also held C, C would stay when Lee leaves.
        let kim_and_c = [a, b, c];
        let rows = build_list(
            &[
                Offer {
                    holder: user_id_for("Kim"),
                    entries: &kim_and_c,
                },
                offers[2],
                offers[3],
            ],
            &bo,
        );
        assert_eq!(ids(&rows), "CAE");
        assert_eq!(rows[0].holders, vec![user_id_for("Kim")]);
        let _ = (d, e);
    }

    #[test]
    fn merge_hide_saved_block_and_never_count_holders() {
        let a = entry(b'A', "Kim", oct(28));
        let c = entry(b'C', "Lee", oct(29));
        let e = entry(b'E', "Choi", oct(20));
        let d = entry(b'D', "Park", oct(1));
        let everyone = [a.clone(), c.clone(), e.clone()];
        let only_d = [d.clone()];
        let mut f = Fixture::new();

        // Five friends all hold the oldest review; it still loses to newer visits.
        let mut offers: Vec<Offer> = (0..5)
            .map(|i| Offer {
                holder: [i; 16],
                entries: &only_d,
            })
            .collect();
        offers.push(Offer {
            holder: [9; 16],
            entries: &everyone,
        });
        offers.push(Offer {
            holder: [8; 16],
            entries: &everyone,
        });
        let rows = build_list(&offers, &f.inputs(None, None));
        assert_eq!(ids(&rows), "CAE");
        assert_eq!(rows[0].holders, vec![[8; 16], [9; 16]]);

        // Saving C hides it and frees its slot.
        f.saved.insert(c.review_id);
        assert_eq!(ids(&build_list(&offers, &f.inputs(None, None))), "AED");

        // Blocking a reviewer drops their reviews; blocking a sharer drops
        // what they offered.
        f.blocked_reviewers.insert(a.reviewer_id);
        assert_eq!(ids(&build_list(&offers, &f.inputs(None, None))), "ED");
        f.blocked_users.insert([9; 16]);
        f.blocked_users.insert([8; 16]);
        assert_eq!(ids(&build_list(&offers, &f.inputs(None, None))), "D");
    }

    #[test]
    fn a_lied_visit_date_cannot_jump_the_queue() {
        let honest = entry(b'D', "Park", oct(2));
        let mut lie = honest.clone();
        lie.visit_date = oct(30);
        let others = [
            entry(b'A', "Kim", oct(28)),
            entry(b'C', "Lee", oct(29)),
            entry(b'E', "Choi", oct(20)),
        ];
        let h = [honest];
        let l = [lie];
        let f = Fixture::new();
        let rows = build_list(
            &[
                Offer {
                    holder: [1; 16],
                    entries: &h,
                },
                Offer {
                    holder: [2; 16],
                    entries: &l,
                },
                Offer {
                    holder: [3; 16],
                    entries: &others,
                },
            ],
            &f.inputs(None, None),
        );
        assert_eq!(ids(&rows), "CAE");
        // The liar alone can push it in, but the tap check will catch them.
        let rows = build_list(
            &[
                Offer {
                    holder: [2; 16],
                    entries: &l,
                },
                Offer {
                    holder: [3; 16],
                    entries: &others,
                },
            ],
            &f.inputs(None, None),
        );
        assert_eq!(ids(&rows), "DCA");
    }

    #[test]
    fn distance_order_range_and_no_fix() {
        let f = Fixture::new();
        let near = ListEntry {
            review_id: [1; 32],
            ..entry(1, "Kim", oct(1))
        };
        let mut far_place = entry(2, "Lee", oct(2));
        let p = place("kakao:2002", "Alley Dumplings", 37.566_535, 126.977_969); // about 8 km
        far_place.restaurant_id = p.place_id;
        far_place.restaurant_name = p.name;
        far_place.location = p.location;
        let list = [far_place.clone(), near.clone()];
        let offers = [Offer {
            holder: [1; 16],
            entries: &list,
        }];

        let rows = build_list(&offers, &f.inputs(Some(cafe_spot()), None));
        assert_eq!(rows[0].entry.review_id, near.review_id);
        assert_eq!(rows[1].entry.review_id, far_place.review_id);

        let rows = build_list(&offers, &f.inputs(Some(cafe_spot()), Some(3_000)));
        assert_eq!(rows.len(), 1);

        // Without a fix: no distances, no range filter, sorted by name.
        let rows = build_list(&offers, &f.inputs(None, Some(500)));
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].entry.restaurant_name, "Alley Dumplings");
        assert!(rows.iter().all(|r| r.distance_m.is_none()));
    }

    #[test]
    fn same_restaurant_stays_together_and_caps_at_three() {
        let f = Fixture::new();
        let mut list: Vec<ListEntry> = (0..6)
            .map(|i| entry(b'a' + i, &format!("person{i}"), oct(1 + i as u64)))
            .collect();
        let mut other = entry(b'z', "zed", oct(5));
        other.restaurant_id = "kakao:other".into();
        other.restaurant_name = "Other Place".into();
        other.location.lat += 1000; // about 111 m north of Gangnam Noodle House
        list.push(other);
        let rows = build_list(
            &[Offer {
                holder: [1; 16],
                entries: &list,
            }],
            &f.inputs(Some(gangnam().location), None),
        );
        assert_eq!(ids(&rows), "fedz");

        // Malformed entries are dropped.
        let mut bad = entry(b'q', "q", oct(1));
        bad.title = String::new();
        let rows = build_list(
            &[Offer {
                holder: [1; 16],
                entries: &[bad],
            }],
            &f.inputs(None, None),
        );
        assert!(rows.is_empty());
    }
}
