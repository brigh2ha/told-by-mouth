//! Multi-phone simulations over an in-memory stand-in for Bluetooth.
//!
//! Every phone is a real `Node`. Frames are cut into 512-byte chunks and
//! delivered in order, the way the native Bluetooth code will do it. A tamper
//! hook lets a test play a dishonest phone.

use std::collections::{BTreeMap, VecDeque};

use tbm_core::advert::Token;
use tbm_core::crypto::{sha256, Hash};
use tbm_core::geo::GeoPoint;
use tbm_core::limits::{DAY, HOLDER_RETRY_MS, HOUR, LINK_CHUNK, SAVED_LIMIT};
use tbm_core::list::ListRow;
use tbm_core::model::{Fix, Place};
use tbm_core::review::Draft;
use tbm_core::store::Store;
use tbm_core::testkit::*;
use tbm_core::wire::{chunks, FrameReader, Message};
use tbm_core::{Action, Error, Event, LinkId, Node};

/// 2026-10-01 00:00 UTC.
const OCT_1: u64 = 1_790_812_800;
fn oct(day: u64) -> u64 {
    OCT_1 + (day - 1) * DAY
}
fn sep(day: u64) -> u64 {
    OCT_1 - 30 * DAY + (day - 1) * DAY
}
/// "Now" in the café: Oct 30, noon.
const NOW: u64 = OCT_1 + 29 * DAY + 12 * HOUR;

type Tamper = Box<dyn FnMut(Message) -> Message>;

struct Phone {
    name: String,
    node: Node,
    token: Token,
    events: Vec<Event>,
    tamper: Option<Tamper>,
    /// Drop everything this phone sends (it has gone quiet).
    mute: bool,
}

struct Sim {
    world: World,
    phones: Vec<Phone>,
    /// Link id to the two phones (connector first).
    links: BTreeMap<LinkId, (usize, usize)>,
    next_link: LinkId,
    clock_ms: u64,
    /// Added to the clock for every delivered frame.
    latency_ms: u64,
    /// Every close with a token ignore, as (phone, link).
    ignored_closes: Vec<(usize, LinkId)>,
}

impl Sim {
    fn new() -> Self {
        Self {
            world: World::new(),
            phones: Vec::new(),
            links: BTreeMap::new(),
            next_link: 1,
            clock_ms: NOW * 1000,
            latency_ms: 5,
            ignored_closes: Vec::new(),
        }
    }

    fn now(&self) -> u64 {
        self.clock_ms / 1000
    }

    fn add(&mut self, name: &str) -> usize {
        let person = self.world.person(name);
        self.add_person(name, person)
    }

    fn add_person(&mut self, name: &str, person: Person) -> usize {
        let mut node = Node::new(Store::new(), self.world.trust.clone(), person.key.clone());
        node.set_identity(person.cert.clone()).unwrap();
        let i = self.phones.len();
        self.phones.push(Phone {
            name: name.into(),
            node,
            token: sha256(name.as_bytes())[..4].try_into().unwrap(),
            events: Vec::new(),
            tamper: None,
            mute: false,
        });
        i
    }

    fn by_token(&self, token: Token) -> usize {
        self.phones.iter().position(|p| p.token == token).unwrap()
    }

    /// Collects `place` at `taken_at` through the node, stamps it and
    /// writes a review an hour later.
    fn write(&mut self, i: usize, place: Place, taken_at: u64, title: &str) -> Hash {
        let visit_id = self.collect(i, place, taken_at);
        let p = &mut self.phones[i];
        let draft = Draft {
            title: title.into(),
            text: format!("{title}, says {}.", p.name),
            photo: Some(format!("photo of {title}").into_bytes()),
        };
        p.node
            .write_review(&visit_id, &draft, (taken_at + HOUR) * 1000)
            .unwrap()
    }

    fn collect(&mut self, i: usize, place: Place, taken_at: u64) -> Hash {
        let p = &mut self.phones[i];
        let fix = Fix {
            taken_at,
            location: place.location,
            accuracy_m: 12,
        };
        let photo = sha256(format!("{}{}{taken_at}", p.name, place.place_id).as_bytes());
        let visit_id = p.node.collect(place, photo, fix).unwrap();
        let stamp = self.world.stamp(&visit_id, taken_at + 60);
        self.phones[i].node.stamp_visit(&visit_id, stamp).unwrap();
        visit_id
    }

    /// `a` connects to `b` and both run the handshake.
    fn meet(&mut self, a: usize, b: usize) -> LinkId {
        let link = self.next_link;
        self.next_link += 1;
        self.links.insert(link, (a, b));
        let now = self.clock_ms;
        let mut work = Vec::new();
        let (ta, tb) = (self.phones[a].token, self.phones[b].token);
        work.extend(
            self.phones[a]
                .node
                .link_opened(link, tb, now)
                .into_iter()
                .map(|x| (a, x)),
        );
        work.extend(
            self.phones[b]
                .node
                .link_opened(link, ta, now)
                .into_iter()
                .map(|x| (b, x)),
        );
        self.run(work);
        link
    }

    fn other(&self, link: LinkId, me: usize) -> Option<usize> {
        self.links
            .get(&link)
            .map(|&(a, b)| if a == me { b } else { a })
    }

    fn link_between(&self, a: usize, b: usize) -> Option<LinkId> {
        self.links
            .iter()
            .find(|(_, &(x, y))| (x, y) == (a, b) || (x, y) == (b, a))
            .map(|(l, _)| *l)
    }

    /// Performs actions until nothing is left to do.
    fn run(&mut self, start: Vec<(usize, Action)>) {
        let mut queue: VecDeque<(usize, Action)> = start.into();
        while let Some((from, action)) = queue.pop_front() {
            match action {
                Action::Send { link, frame } => {
                    let Some(to) = self.other(link, from) else {
                        continue;
                    };
                    if self.phones[from].mute {
                        continue;
                    }
                    let frame = match self.phones[from].tamper.as_mut() {
                        Some(t) => {
                            let mut r = FrameReader::new();
                            let msg = r.push(&frame).unwrap().remove(0);
                            t(msg).to_frame()
                        }
                        None => frame,
                    };
                    self.clock_ms += self.latency_ms;
                    let now = self.clock_ms;
                    for c in chunks(&frame, LINK_CHUNK) {
                        assert!(c.len() <= LINK_CHUNK);
                        let out = self.phones[to].node.receive(link, &c, now);
                        queue.extend(out.into_iter().map(|a| (to, a)));
                    }
                }
                Action::Close {
                    link,
                    ignore_token_secs,
                } => {
                    if ignore_token_secs > 0 {
                        self.ignored_closes.push((from, link));
                    }
                    if let Some(to) = self.other(link, from) {
                        self.phones[to].node.link_closed(link);
                        self.phones[from].node.link_closed(link);
                    }
                    self.links.remove(&link);
                }
                Action::Connect { token } => {
                    let to = self.by_token(token);
                    if self.link_between(from, to).is_none() {
                        let link = self.next_link;
                        self.next_link += 1;
                        self.links.insert(link, (from, to));
                        let now = self.clock_ms;
                        let a = self.phones[from].node.link_opened(link, token, now);
                        let from_token = self.phones[from].token;
                        let b = self.phones[to].node.link_opened(link, from_token, now);
                        queue.extend(a.into_iter().map(|x| (from, x)));
                        queue.extend(b.into_iter().map(|x| (to, x)));
                    }
                }
            }
        }
        for p in &mut self.phones {
            let ev = p.node.take_events();
            p.events.extend(ev);
        }
    }

    /// Phone `i` walks away: links close and everyone forgets them.
    fn leave(&mut self, i: usize) {
        let links: Vec<LinkId> = self
            .links
            .iter()
            .filter(|(_, &(a, b))| a == i || b == i)
            .map(|(l, _)| *l)
            .collect();
        for l in links {
            let (a, b) = self.links.remove(&l).unwrap();
            self.phones[a].node.link_closed(l);
            self.phones[b].node.link_closed(l);
        }
        let token = self.phones[i].token;
        let now = self.clock_ms;
        let mut work = Vec::new();
        for (j, p) in self.phones.iter_mut().enumerate() {
            if j != i {
                work.extend(p.node.person_left(token, now).into_iter().map(|a| (j, a)));
            }
        }
        self.run(work);
    }

    fn act(&mut self, i: usize, f: impl FnOnce(&mut Node, u64) -> Vec<Action>) {
        let now = self.clock_ms;
        let actions = f(&mut self.phones[i].node, now);
        self.run(actions.into_iter().map(|a| (i, a)).collect());
    }

    fn list(&self, i: usize, at: Option<GeoPoint>) -> Vec<ListRow> {
        self.phones[i].node.list(at)
    }

    fn take_events(&mut self, i: usize) -> Vec<Event> {
        std::mem::take(&mut self.phones[i].events)
    }
}

fn titles(rows: &[ListRow]) -> Vec<&str> {
    rows.iter().map(|r| r.entry.title.as_str()).collect()
}

/// Sets up the spec's worked example: Bo in a café with Kim (A, B), Lee (C),
/// Park (D) and Choi (E), all reviews of Gangnam Noodle House.
fn worked_example() -> (Sim, [usize; 5]) {
    let mut s = Sim::new();
    let bo = s.add("Bo");
    let kim = s.add("Kim");
    let lee = s.add("Lee");
    let park = s.add("Park");
    let choi = s.add("Choi");
    s.write(kim, gangnam(), oct(28), "A");
    s.write(kim, gangnam(), oct(10), "B");
    s.write(lee, gangnam(), oct(29), "C");
    s.write(park, gangnam(), sep(2), "D");
    s.write(choi, gangnam(), oct(20), "E");
    for p in [kim, lee, park, choi] {
        s.meet(p, bo);
    }
    (s, [bo, kim, lee, park, choi])
}

#[test]
fn worked_example_shows_c_a_e_and_d_moves_up_when_lee_leaves() {
    let (mut s, [bo, _kim, lee, _park, _choi]) = worked_example();
    let rows = s.list(bo, Some(cafe_spot()));
    assert_eq!(titles(&rows), ["C", "A", "E"]);
    for r in &rows {
        assert_eq!(r.entry.restaurant_name, "Gangnam Noodle House");
        let d = r.distance_m.unwrap();
        assert!((1_150.0..1_250.0).contains(&d), "{d}");
    }
    assert!(s
        .take_events(bo)
        .iter()
        .any(|e| matches!(e, Event::PeerMet { real_name, .. } if real_name == "Lee")));

    s.leave(lee);
    assert_eq!(titles(&s.list(bo, Some(cafe_spot()))), ["A", "E", "D"]);
    assert!(s.take_events(bo).contains(&Event::ListChanged));
}

#[test]
fn tap_verify_save_and_told_by_notes_travel_on() {
    let (mut s, [bo, _kim, lee, _park, _choi]) = worked_example();
    let c = s.list(bo, None)[0].entry.review_id;

    // Bo taps C; Lee is asked and the full review arrives and checks out.
    s.act(bo, |n, now| n.open_review(c, now));
    assert!(s
        .take_events(bo)
        .contains(&Event::ReviewOpened { review_id: c }));
    let opened = s.phones[bo].node.opened(&c).unwrap().clone();
    assert_eq!(opened.review.body.reviewer.real_name, "Lee");
    assert_eq!(opened.sharer_name, "Lee");
    assert_eq!(opened.sharer_told_count, 0);
    assert_eq!(opened.photo.as_deref(), Some(&b"photo of C"[..]));

    // Save: "Lee ate here and told you".
    let v0 = s.phones[bo].node.store().catalog_version();
    s.phones[bo].node.save_review(&c, s.clock_ms).unwrap();
    let saved = s.phones[bo].node.store().saved_review(&c).unwrap().clone();
    let told = saved.told.as_ref().unwrap();
    assert_eq!((told.told_count, told.teller_name.as_str()), (1, "Lee"));
    assert_eq!(s.phones[bo].node.store().catalog_version(), v0 + 1);
    // Saved reviews are hidden and free their slot.
    assert_eq!(titles(&s.list(bo, None)), ["A", "E", "D"]);

    // Lee leaves; Bo walks on and meets Han, who has never met Lee.
    s.leave(lee);
    let han = s.add("Han");
    s.meet(han, bo);
    let rows = s.list(han, None);
    let row = rows.iter().find(|r| r.entry.review_id == c).unwrap();
    assert_eq!(row.holders.len(), 1);
    s.act(han, |n, now| n.open_review(c, now));
    let opened = s.phones[han].node.opened(&c).unwrap();
    assert_eq!(
        (opened.sharer_name.as_str(), opened.sharer_told_count),
        ("Bo", 1)
    );
    s.phones[han].node.save_review(&c, s.clock_ms).unwrap();
    let told = s.phones[han]
        .node
        .store()
        .saved_review(&c)
        .unwrap()
        .told
        .clone()
        .unwrap();
    // "Lee ate here, told through 2 people, last by Bo."
    assert_eq!((told.told_count, told.teller_name.as_str()), (2, "Bo"));
    // The review itself is byte-for-byte the one Lee signed.
    assert_eq!(
        s.phones[han].node.store().saved_review(&c).unwrap().review,
        saved.review
    );
}

#[test]
fn not_saving_keeps_nothing() {
    let (mut s, [bo, ..]) = worked_example();
    let a = s.list(bo, None)[1].entry.review_id;
    s.act(bo, |n, now| n.open_review(a, now));
    assert!(s.phones[bo].node.opened(&a).is_some());
    s.phones[bo].node.close_review(&a);
    assert!(s.phones[bo].node.opened(&a).is_none());
    assert_eq!(s.phones[bo].node.store().saved().count(), 0);
}

#[test]
fn a_lied_visit_date_is_caught_at_tap_and_the_liar_is_ignored() {
    let (mut s, [bo, _kim, _lee, park, _choi]) = worked_example();
    // Mallory holds Park's review D and claims a newer visit to jump the queue.
    let mallory = s.add("Mallory");
    s.meet(park, mallory);
    let d = s
        .list(mallory, None)
        .iter()
        .find(|r| r.entry.title == "D")
        .unwrap()
        .entry
        .review_id;
    s.act(mallory, |n, now| n.open_review(d, now));
    s.phones[mallory].node.save_review(&d, s.clock_ms).unwrap();
    s.leave(park);

    s.phones[mallory].tamper = Some(Box::new(|m| match m {
        Message::Catalog(mut c) => {
            for e in &mut c.entries {
                e.visit_date = oct(30);
            }
            Message::Catalog(c)
        }
        m => m,
    }));
    s.meet(mallory, bo);
    assert_eq!(titles(&s.list(bo, None)), ["D", "C", "A"]);

    s.act(bo, |n, now| n.open_review(d, now));
    let ev = s.take_events(bo);
    let mallory_id = user_id_for("Mallory");
    assert!(ev.contains(&Event::SharerIgnored {
        user_id: mallory_id,
        reason: Error::EntryMismatch("visit date"),
    }));
    assert!(ev.contains(&Event::ReviewUnavailable { review_id: d }));
    assert!(s.phones[bo].node.opened(&d).is_none());
    // The list is rebuilt without Mallory's entries.
    assert_eq!(titles(&s.list(bo, None)), ["C", "A", "E"]);
    assert!(s.phones[bo]
        .node
        .nearby()
        .iter()
        .any(|p| p.real_name == "Mallory" && p.ignored));
}

#[test]
fn an_edited_review_is_thrown_away_and_the_next_holder_is_asked() {
    let (mut s, [bo, kim, lee, ..]) = worked_example();
    // Kim also holds Lee's review C.
    s.meet(lee, kim);
    let c = s
        .list(kim, None)
        .iter()
        .find(|r| r.entry.title == "C")
        .unwrap()
        .entry
        .review_id;
    s.act(kim, |n, now| n.open_review(c, now));
    s.phones[kim].node.save_review(&c, s.clock_ms).unwrap();
    // Make Kim's newer catalog reach Bo.
    let kim_token = s.phones[kim].token;
    let v = s.phones[kim].node.store().catalog_version() as u16;
    s.act(bo, |n, _| n.advert_seen(kim_token, v));
    let row = s
        .list(bo, None)
        .into_iter()
        .find(|r| r.entry.review_id == c)
        .unwrap();
    assert_eq!(row.holders.len(), 2);

    // Holders are asked in user-id order; the first one edits the text.
    let (liar, honest) = if user_id_for("Kim") < user_id_for("Lee") {
        (kim, lee)
    } else {
        (lee, kim)
    };
    s.phones[liar].tamper = Some(Box::new(|m| match m {
        Message::Review {
            mut review,
            photo,
            told_count,
        } => {
            review.body.text = "Terrible, avoid.".into();
            Message::Review {
                review,
                photo,
                told_count,
            }
        }
        m => m,
    }));
    s.act(bo, |n, now| n.open_review(c, now));
    let opened = s.phones[bo]
        .node
        .opened(&c)
        .expect("opened from the honest holder");
    assert_eq!(opened.sharer_name, s.phones[honest].name);
    assert!(opened.review.body.text.contains("says Lee"));
    let liar_id = user_id_for(&s.phones[liar].name.clone());
    assert!(s.take_events(bo).contains(&Event::SharerIgnored {
        user_id: liar_id,
        reason: Error::IdMismatch("review"),
    }));
}

#[test]
fn holder_that_goes_quiet_is_retried_after_ten_seconds() {
    let (mut s, [bo, kim, lee, ..]) = worked_example();
    s.meet(lee, kim);
    let c = s
        .list(kim, None)
        .iter()
        .find(|r| r.entry.title == "C")
        .unwrap()
        .entry
        .review_id;
    s.act(kim, |n, now| n.open_review(c, now));
    s.phones[kim].node.save_review(&c, s.clock_ms).unwrap();
    let kim_token = s.phones[kim].token;
    let v = s.phones[kim].node.store().catalog_version() as u16;
    s.act(bo, |n, _| n.advert_seen(kim_token, v));

    // Whoever is asked first says nothing.
    let first = if user_id_for("Kim") < user_id_for("Lee") {
        kim
    } else {
        lee
    };
    s.phones[first].mute = true;
    s.act(bo, |n, now| n.open_review(c, now));
    assert!(s.phones[bo].node.opened(&c).is_none());
    s.phones[first].mute = false;
    s.clock_ms += HOLDER_RETRY_MS;
    s.act(bo, |n, now| n.tick(now));
    assert!(s.phones[bo].node.opened(&c).is_some());
}

#[test]
fn deleted_review_answers_not_found() {
    let (mut s, [bo, _kim, lee, ..]) = worked_example();
    let c = s.list(bo, None)[0].entry.review_id;
    assert!(s.phones[lee].node.delete_review(&c));
    s.act(bo, |n, now| n.open_review(c, now));
    assert!(s
        .take_events(bo)
        .contains(&Event::ReviewUnavailable { review_id: c }));
    assert_eq!(titles(&s.list(bo, None)), ["A", "E", "D"]);
}

#[test]
fn a_new_catalog_version_is_downloaded() {
    let (mut s, [bo, kim, ..]) = worked_example();
    let place = tbm_core::testkit::place("kakao:77", "Bibim Bar", 37.509, 127.028);
    s.write(kim, place, oct(29), "Crispy rice");
    // Nothing changes until Bo sees Kim's new version in the advertisement.
    assert_eq!(s.list(bo, None).len(), 3);
    let kim_token = s.phones[kim].token;
    let v = s.phones[kim].node.store().catalog_version() as u16;
    s.act(bo, |n, _| n.advert_seen(kim_token, v));
    let rows = s.list(bo, Some(cafe_spot()));
    // Bibim Bar is nearer to the café, so it comes first.
    assert_eq!(titles(&rows), ["Crispy rice", "C", "A", "E"]);
    // Seeing the same version again costs nothing.
    let actions = s.phones[bo].node.advert_seen(kim_token, v);
    assert!(actions.is_empty());
}

#[test]
fn reconnects_when_needed_after_an_idle_link_closes() {
    let (mut s, [bo, _kim, lee, ..]) = worked_example();
    let link = s.link_between(lee, bo).unwrap();
    // The idle link closes but Lee is still nearby.
    s.links.remove(&link);
    s.phones[bo].node.link_closed(link);
    s.phones[lee].node.link_closed(link);
    let c = s.list(bo, None)[0].entry.review_id;
    s.act(bo, |n, now| n.open_review(c, now));
    assert!(s.phones[bo].node.opened(&c).is_some());
    assert!(s.link_between(lee, bo).is_some());
}

#[test]
fn trade_swaps_cards_with_both_signatures() {
    let mut s = Sim::new();
    let kim = s.add("Kim");
    let lee = s.add("Lee");
    s.collect(kim, gangnam(), oct(28));
    s.collect(
        lee,
        place("kakao:9", "Alley Dumplings", 37.51, 127.03),
        oct(27),
    );
    let kim_card = s.phones[kim].node.store().cards().next().unwrap().clone();
    let lee_card = s.phones[lee].node.store().cards().next().unwrap().clone();
    let link = s.meet(kim, lee);

    s.act(kim, |n, now| n.trade_start(link, now).unwrap());
    assert!(s.take_events(lee).contains(&Event::TradeStarted { link }));
    let kc = kim_card.card_id;
    let lc = lee_card.card_id;
    s.act(kim, |n, now| n.trade_offer(link, &kc, now).unwrap());
    s.act(lee, |n, now| n.trade_offer(link, &lc, now).unwrap());
    s.act(kim, |n, _| n.trade_confirm(link).unwrap());
    // Only one confirm: nothing has moved yet.
    assert_eq!(
        s.phones[kim].node.store().cards().next().unwrap().card_id,
        kc
    );
    s.act(lee, |n, _| n.trade_confirm(link).unwrap());

    let kim_cards: Vec<_> = s.phones[kim].node.store().cards().cloned().collect();
    let lee_cards: Vec<_> = s.phones[lee].node.store().cards().cloned().collect();
    assert_eq!(kim_cards.len(), 1);
    assert_eq!(kim_cards[0].card_id, lc);
    assert_eq!(lee_cards[0].card_id, kc);
    assert_eq!(kim_cards[0].history.len(), 1);
    assert_eq!(kim_cards[0].history, lee_cards[0].history);
    let record = &kim_cards[0].history[0];
    let key = |i: usize| {
        s.phones[i]
            .node
            .store()
            .identity
            .as_ref()
            .unwrap()
            .device_key
    };
    let (ka, kb) = if user_id_for("Kim") < user_id_for("Lee") {
        (key(kim), key(lee))
    } else {
        (key(lee), key(kim))
    };
    tbm_core::trade::verify_record(record, &ka, &kb).unwrap();
    assert!(s
        .take_events(kim)
        .iter()
        .any(|e| matches!(e, Event::TradeCompleted { .. })));

    // A traded card never lets you write a review.
    let visit = lee_card.origin_visit;
    let err = s.phones[kim]
        .node
        .write_review(&visit, &draft("Mine now?", "No."), s.clock_ms)
        .unwrap_err();
    assert_eq!(err, Error::NotMyVisit);
}

#[test]
fn trade_cancelled_or_dropped_link_changes_nothing() {
    let mut s = Sim::new();
    let kim = s.add("Kim");
    let lee = s.add("Lee");
    s.collect(kim, gangnam(), oct(28));
    s.collect(
        lee,
        place("kakao:9", "Alley Dumplings", 37.51, 127.03),
        oct(27),
    );
    let kc = s.phones[kim].node.store().cards().next().unwrap().card_id;
    let lc = s.phones[lee].node.store().cards().next().unwrap().card_id;
    let link = s.meet(kim, lee);
    s.act(kim, |n, now| n.trade_start(link, now).unwrap());
    s.act(kim, |n, now| n.trade_offer(link, &kc, now).unwrap());
    s.act(lee, |n, now| n.trade_offer(link, &lc, now).unwrap());
    s.act(kim, |n, _| n.trade_confirm(link).unwrap());
    // The link drops before Lee confirms.
    s.links.remove(&link);
    s.phones[kim].node.link_closed(link);
    s.phones[lee].node.link_closed(link);
    assert_eq!(
        s.phones[kim].node.store().cards().next().unwrap().card_id,
        kc
    );
    assert_eq!(
        s.phones[lee].node.store().cards().next().unwrap().card_id,
        lc
    );
    assert!(s.phones[kim]
        .node
        .take_events()
        .contains(&Event::TradeCancelled { link }));
}

#[test]
fn revocation_drops_saved_reviews_and_blocks_meetings() {
    let (mut s, [bo, kim, ..]) = worked_example();
    let a = s.list(bo, None)[1].entry.review_id;
    s.act(bo, |n, now| n.open_review(a, now));
    s.phones[bo].node.save_review(&a, s.clock_ms).unwrap();
    assert_eq!(s.phones[bo].node.store().saved().count(), 1);

    let list = s.world.revoke_users(&[user_id_for("Kim")], s.now());
    let dropped = s.phones[bo]
        .node
        .update_revocations(list.clone(), s.clock_ms)
        .unwrap();
    assert_eq!(dropped, 1);
    assert_eq!(s.phones[bo].node.store().saved().count(), 0);
    // Kim's offers are ignored from now on.
    assert!(!titles(&s.list(bo, None)).contains(&"A"));

    // A fresh meeting with Kim fails at the handshake and ignores the token.
    s.leave(kim);
    s.meet(kim, bo);
    assert!(s.ignored_closes.iter().any(|&(p, _)| p == bo));
    assert!(s.take_events(bo).iter().any(|e| matches!(
        e,
        Event::LinkFailed {
            reason: Error::Revoked,
            ..
        }
    )));
}

#[test]
fn expired_certificate_can_browse_only() {
    let mut s = Sim::new();
    let kim = s.add("Kim");
    s.write(kim, gangnam(), oct(28), "A");
    let old_person = s.world.person_at("Old", NOW - 400 * DAY);
    let old = s.add_person("Old", old_person);
    s.meet(old, kim);

    // Old can browse and read Kim's review...
    let rows = s.list(old, None);
    assert_eq!(titles(&rows), ["A"]);
    let a = rows[0].entry.review_id;
    s.act(old, |n, now| n.open_review(a, now));
    assert!(s.phones[old].node.opened(&a).is_some());
    // ...but cannot save, write or trade.
    assert_eq!(
        s.phones[old].node.save_review(&a, s.clock_ms),
        Err(Error::CertificateExpired)
    );
    let link = s.link_between(old, kim).unwrap();
    assert!(s.phones[old].node.trade_start(link, s.clock_ms).is_err());
    assert!(s.phones[kim].node.trade_start(link, s.clock_ms).is_err());
    // Kim sees Old as browse-only and never takes a list from them.
    assert!(s.phones[kim].node.nearby()[0].browse_only);
}

#[test]
fn a_relayed_handshake_that_is_too_slow_fails() {
    let mut s = Sim::new();
    let a = s.add("Kim");
    let b = s.add("Lee");
    s.latency_ms = 600;
    s.meet(a, b);
    assert!(!s.ignored_closes.is_empty());
    assert!(s.phones[a].node.nearby().is_empty() || s.phones[b].node.nearby().is_empty());
    assert!(s
        .take_events(a)
        .into_iter()
        .chain(s.take_events(b))
        .any(|e| matches!(
            e,
            Event::LinkFailed {
                reason: Error::TooSlow,
                ..
            }
        )));
}

#[test]
fn blocked_people_disappear() {
    let (mut s, [bo, kim, ..]) = worked_example();
    s.act(bo, |n, _| n.block(user_id_for("Kim")));
    let t = titles(&s.list(bo, None)).join("");
    assert_eq!(t, "CED");
    // Kim cannot meet Bo again.
    s.meet(kim, bo);
    assert!(s.take_events(bo).iter().any(|e| matches!(
        e,
        Event::LinkFailed {
            reason: Error::Blocked,
            ..
        }
    )));
}

#[test]
fn rate_limit_on_get_review() {
    let (mut s, [bo, _kim, lee, ..]) = worked_example();
    let c = s.list(bo, None)[0].entry.review_id;
    let link = s.link_between(lee, bo).unwrap();
    let frame = Message::GetReview { review_id: c }.to_frame();
    let mut answered = 0;
    for _ in 0..40 {
        let out = s.phones[lee].node.receive(link, &frame, s.clock_ms);
        answered += out.len();
    }
    assert_eq!(answered, 30);
    s.clock_ms += 61_000;
    assert_eq!(
        s.phones[lee].node.receive(link, &frame, s.clock_ms).len(),
        1
    );
}

#[test]
fn store_survives_a_restart_and_enforces_the_saved_limit() {
    let (mut s, [bo, ..]) = worked_example();
    let c = s.list(bo, None)[0].entry.review_id;
    s.act(bo, |n, now| n.open_review(c, now));
    s.phones[bo].node.save_review(&c, s.clock_ms).unwrap();
    s.write(bo, gangnam(), oct(29), "Bo's own");

    use tbm_core::cbor::Cbor;
    let blob = s.phones[bo].node.store().to_cbor();
    let back = Store::from_cbor(&blob).unwrap();
    assert_eq!(&back, s.phones[bo].node.store());
    assert_eq!(back.saved_from_others(), 1);
    assert_eq!(back.catalog().entries.len(), 2);
    assert_eq!(SAVED_LIMIT, 1000);
}

#[test]
fn one_review_per_visit_but_a_new_visit_allows_another() {
    let mut s = Sim::new();
    let kim = s.add("Kim");
    let v1 = s.collect(kim, gangnam(), oct(20));
    let n = &mut s.phones[kim].node;
    n.write_review(&v1, &draft("First", "Good."), oct(21) * 1000)
        .unwrap();
    assert_eq!(
        n.write_review(&v1, &draft("Again", "Still good."), oct(21) * 1000),
        Err(Error::AlreadyReviewed)
    );
    let v2 = s.collect(kim, gangnam(), oct(28));
    s.phones[kim]
        .node
        .write_review(&v2, &draft("Changed my mind", "Worse now."), oct(28) * 1000)
        .unwrap();
    assert_eq!(s.phones[kim].node.store().catalog().entries.len(), 2);
}
