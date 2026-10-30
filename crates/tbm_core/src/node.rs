//! One phone's core: the object the native apps hold and call.
//!
//! It does no I/O. The Bluetooth code tells it when links open and close,
//! hands it received bytes, and performs the [`Action`]s it returns (send a
//! frame, close a link, connect to someone). Things the screens care about
//! come out as [`Event`]s. Time is passed in as milliseconds since 1970.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use crate::advert::{version_changed, Token};
use crate::collect::{apply_stamp, new_visit};
use crate::crypto::{random_bytes, Hash, Signer};
use crate::error::Error;
use crate::geo::GeoPoint;
use crate::limits::{Time, GET_REVIEW_PER_MINUTE, HOLDER_RETRY_MS, IGNORE_TOKEN_SECS};
use crate::list::{build_list, ListInputs, ListRow, Offer};
use crate::meeting::{Handshake, Met};
use crate::model::{
    Card, Catalog, Certificate, Fix, Place, Review, SavedReview, Stamp, ToldBy, TradeRecord, UserId,
};
use crate::review::{check_entry, verify_review, write_review, Draft};
use crate::store::{own_saved, Store};
use crate::trade::Trade;
use crate::trust::Trust;
use crate::wire::{FrameReader, Message};

/// A link id chosen by the Bluetooth code, unique while the link is open.
pub type LinkId = u64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Send this frame, cut into chunks of at most `LINK_CHUNK` bytes.
    Send { link: LinkId, frame: Vec<u8> },
    /// Close the link; if `ignore_token_secs` is not 0, ignore the other
    /// phone's advertisement token that long.
    Close {
        link: LinkId,
        ignore_token_secs: u64,
    },
    /// Please open a link to the phone advertising this token.
    Connect { token: Token },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    PeerMet {
        user_id: UserId,
        real_name: String,
        browse_only: bool,
    },
    PeerLeft {
        user_id: UserId,
    },
    /// Rebuild the list (call [`Node::list`]).
    ListChanged,
    ReviewOpened {
        review_id: Hash,
    },
    /// Nobody nearby still has it; the entry disappears.
    ReviewUnavailable {
        review_id: Hash,
    },
    /// A sharer sent something false and is ignored for the rest of the meeting.
    SharerIgnored {
        user_id: UserId,
        reason: Error,
    },
    LinkFailed {
        link: LinkId,
        reason: Error,
    },
    TradeStarted {
        link: LinkId,
    },
    TradeOffered {
        link: LinkId,
        card: Card,
    },
    TradePeerConfirmed {
        link: LinkId,
    },
    TradeCompleted {
        link: LinkId,
        record: TradeRecord,
    },
    TradeCancelled {
        link: LinkId,
    },
}

/// A full review I opened and can read, save or close.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedReview {
    pub review: Review,
    pub photo: Option<Vec<u8>>,
    pub sharer: UserId,
    pub sharer_name: String,
    /// 0 if the sharer wrote it.
    pub sharer_told_count: u16,
}

/// Someone nearby, for the screens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nearby {
    pub user_id: UserId,
    pub real_name: String,
    pub browse_only: bool,
    pub ignored: bool,
    pub linked: bool,
}

struct Peer {
    cert: Certificate,
    tokens: BTreeSet<Token>,
    link: Option<LinkId>,
    catalog: Option<Catalog>,
    ignored: bool,
    browse_only: bool,
    /// When I answered their GET_REVIEWs, for the rate limit.
    served: VecDeque<u64>,
    /// Messages waiting for a link to them.
    queued: Vec<Message>,
}

struct Link {
    token: Token,
    reader: FrameReader,
    handshake: Handshake,
    peer: Option<UserId>,
    trade: Option<Trade>,
}

struct Pending {
    tried: BTreeSet<UserId>,
    asking: Option<(UserId, u64)>,
}

pub struct Node {
    store: Store,
    trust: Trust,
    signer: Arc<dyn Signer>,
    links: BTreeMap<LinkId, Link>,
    peers: BTreeMap<UserId, Peer>,
    opened: BTreeMap<Hash, OpenedReview>,
    pending: BTreeMap<Hash, Pending>,
    events: Vec<Event>,
}

fn send(link: LinkId, msg: &Message) -> Action {
    Action::Send {
        link,
        frame: msg.to_frame(),
    }
}

fn secs(now_ms: u64) -> Time {
    now_ms / 1000
}

impl Node {
    pub fn new(store: Store, trust: Trust, signer: Arc<dyn Signer>) -> Self {
        Self {
            store,
            trust,
            signer,
            links: BTreeMap::new(),
            peers: BTreeMap::new(),
            opened: BTreeMap::new(),
            pending: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn trust(&self) -> &Trust {
        &self.trust
    }

    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// My certificate, if it lets me write, share, save and trade now.
    fn active_identity(&self, now: Time) -> Result<&Certificate, Error> {
        let cert = self.store.identity.as_ref().ok_or(Error::NoIdentity)?;
        if self.trust.is_revoked(cert, now) {
            return Err(Error::Revoked);
        }
        if now > cert.expires_at {
            return Err(Error::CertificateExpired);
        }
        Ok(cert)
    }

    /// Installs a new or renewed certificate for my key.
    pub fn set_identity(&mut self, cert: Certificate) -> Result<(), Error> {
        self.trust.verify_certificate(&cert)?;
        if cert.device_key != self.signer.public_key() {
            return Err(Error::BadKey);
        }
        self.store.identity = Some(cert);
        Ok(())
    }

    pub fn set_range(&mut self, range_m: Option<u32>) {
        self.store.range_m = range_m;
        self.events.push(Event::ListChanged);
    }

    // ------------------------------------------------------------ collect and write

    /// Builds and signs a Visit for an in-app photo. Returns its id; it
    /// waits for a stamp from the server.
    pub fn collect(&mut self, place: Place, photo_hash: Hash, fix: Fix) -> Result<Hash, Error> {
        let user = self
            .store
            .identity
            .as_ref()
            .ok_or(Error::NoIdentity)?
            .user_id;
        let visit = new_visit(&*self.signer, user, place, photo_hash, fix)?;
        let id = visit.visit_id;
        self.store.visits.insert(id, visit);
        Ok(id)
    }

    /// Accepts the server's stamp; the visit becomes a Card.
    pub fn stamp_visit(&mut self, visit_id: &Hash, stamp: Stamp) -> Result<Hash, Error> {
        let visit = self.store.visits.get_mut(visit_id).ok_or(Error::NotFound)?;
        apply_stamp(visit, stamp, &self.trust)?;
        let card = Card::from_visit(visit);
        let id = card.card_id;
        self.store.cards.entry(id).or_insert(card);
        Ok(id)
    }

    pub fn write_review(
        &mut self,
        visit_id: &Hash,
        draft: &Draft,
        now_ms: u64,
    ) -> Result<Hash, Error> {
        let now = secs(now_ms);
        let me = self.store.identity.as_ref().ok_or(Error::NoIdentity)?;
        let visit = self.store.visits.get(visit_id).ok_or(Error::NotMyVisit)?;
        let review = write_review(
            me,
            &*self.signer,
            &self.trust,
            visit,
            self.store.is_reviewed(visit_id),
            draft,
            now,
        )?;
        let id = review.review_id;
        self.store
            .put_saved(own_saved(review, draft.photo.clone(), now))?;
        self.events.push(Event::ListChanged);
        Ok(id)
    }

    // ------------------------------------------------------------ links

    /// A Bluetooth link opened (either side connected). Sends HELLO.
    pub fn link_opened(&mut self, link: LinkId, token: Token, _now_ms: u64) -> Vec<Action> {
        let Some(cert) = &self.store.identity else {
            return vec![Action::Close {
                link,
                ignore_token_secs: 0,
            }];
        };
        let (handshake, hello) =
            Handshake::start(cert, self.store.catalog_version(), random_bytes());
        self.links.insert(
            link,
            Link {
                token,
                reader: FrameReader::new(),
                handshake,
                peer: None,
                trade: None,
            },
        );
        vec![send(link, &hello)]
    }

    /// The link closed. The person may still be nearby (links close when
    /// idle); their list stays until [`Node::person_left`].
    pub fn link_closed(&mut self, link: LinkId) {
        let Some(l) = self.links.remove(&link) else {
            return;
        };
        if l.trade.is_some() {
            self.events.push(Event::TradeCancelled { link });
        }
        if let Some(peer) = l.peer.and_then(|u| self.peers.get_mut(&u)) {
            if peer.link == Some(link) {
                peer.link = None;
            }
        }
    }

    /// Bytes arrived on a link (chunks, in order).
    pub fn receive(&mut self, link: LinkId, bytes: &[u8], now_ms: u64) -> Vec<Action> {
        let Some(l) = self.links.get_mut(&link) else {
            return vec![];
        };
        let msgs = match l.reader.push(bytes) {
            Ok(m) => m,
            Err(e) => return self.fail_link(link, e),
        };
        let mut out = Vec::new();
        for m in msgs {
            out.extend(self.handle(link, m, now_ms));
            if !self.links.contains_key(&link) {
                break;
            }
        }
        out
    }

    /// The person advertising `token` has not been heard from for a while.
    pub fn person_left(&mut self, token: Token, now_ms: u64) -> Vec<Action> {
        let Some(user) = self.peer_by_token(&token) else {
            return vec![];
        };
        let peer = self.peers.get_mut(&user).unwrap();
        peer.tokens.remove(&token);
        if !peer.tokens.is_empty() {
            return vec![];
        }
        self.peers.remove(&user);
        self.events.push(Event::PeerLeft { user_id: user });
        self.events.push(Event::ListChanged);
        // Anyone waiting on them moves to the next holder now.
        let waiting: Vec<Hash> = self
            .pending
            .iter()
            .filter(|(_, p)| p.asking.is_some_and(|(u, _)| u == user))
            .map(|(id, _)| *id)
            .collect();
        waiting
            .into_iter()
            .flat_map(|id| self.advance(id, now_ms))
            .collect()
    }

    /// An advertisement was seen with this token and catalog version.
    pub fn advert_seen(&mut self, token: Token, version_low16: u16) -> Vec<Action> {
        let Some(user) = self.peer_by_token(&token) else {
            // First time we see this token.
            return vec![Action::Connect { token }];
        };
        let peer = &self.peers[&user];
        if peer.ignored || peer.browse_only {
            return vec![];
        }
        let held = peer.catalog.as_ref().map(|c| c.version);
        if held.is_some_and(|v| !version_changed(version_low16, v)) {
            return vec![];
        }
        match peer.link.filter(|l| self.is_met(*l)) {
            Some(link) => vec![send(
                link,
                &Message::GetCatalog {
                    have_version: held.unwrap_or(0),
                },
            )],
            None => vec![Action::Connect { token }],
        }
    }

    /// Call about once a second: retries taps whose holder is not answering.
    pub fn tick(&mut self, now_ms: u64) -> Vec<Action> {
        let due: Vec<Hash> = self
            .pending
            .iter()
            .filter(|(_, p)| {
                p.asking
                    .is_some_and(|(_, at)| now_ms >= at + HOLDER_RETRY_MS)
            })
            .map(|(id, _)| *id)
            .collect();
        due.into_iter()
            .flat_map(|id| self.advance(id, now_ms))
            .collect()
    }

    fn peer_by_token(&self, token: &Token) -> Option<UserId> {
        self.peers
            .iter()
            .find(|(_, p)| p.tokens.contains(token))
            .map(|(u, _)| *u)
    }

    fn is_met(&self, link: LinkId) -> bool {
        self.links
            .get(&link)
            .is_some_and(|l| l.handshake.met().is_some())
    }

    pub fn nearby(&self) -> Vec<Nearby> {
        self.peers
            .values()
            .map(|p| Nearby {
                user_id: p.cert.user_id,
                real_name: p.cert.real_name.clone(),
                browse_only: p.browse_only,
                ignored: p.ignored,
                linked: p.link.is_some(),
            })
            .collect()
    }

    fn fail_link(&mut self, link: LinkId, reason: Error) -> Vec<Action> {
        self.events.push(Event::LinkFailed { link, reason });
        self.link_closed(link);
        vec![Action::Close {
            link,
            ignore_token_secs: IGNORE_TOKEN_SECS,
        }]
    }

    fn handle(&mut self, link: LinkId, msg: Message, now_ms: u64) -> Vec<Action> {
        let me = match &self.store.identity {
            Some(c) => c.user_id,
            None => return self.fail_link(link, Error::NoIdentity),
        };
        let l = self.links.get_mut(&link).expect("link exists");
        match msg {
            Message::Hello(hello) => {
                match l.handshake.on_hello(
                    hello,
                    &*self.signer,
                    &self.trust,
                    &self.store.blocked_users,
                    &me,
                    now_ms,
                ) {
                    Ok(prove) => vec![send(link, &prove)],
                    Err(e) => self.fail_link(link, e),
                }
            }
            Message::Prove(sig) => match l.handshake.on_prove(&sig, now_ms) {
                Ok(met) => {
                    let met = met.clone();
                    self.on_met(link, met)
                }
                Err(e) => self.fail_link(link, e),
            },
            _ if l.handshake.met().is_none() => {
                self.fail_link(link, Error::Protocol("message before handshake"))
            }
            Message::GetCatalog { .. } => {
                let catalog = match self.active_identity(secs(now_ms)) {
                    Ok(_) => self.store.catalog(),
                    // An expired or revoked certificate can browse but not share.
                    Err(_) => Catalog {
                        version: self.store.catalog_version(),
                        entries: vec![],
                    },
                };
                vec![send(link, &Message::Catalog(catalog))]
            }
            Message::Catalog(catalog) => {
                let user = l.peer.expect("met");
                let peer = self.peers.get_mut(&user).expect("peer");
                if !peer.ignored && !peer.browse_only {
                    peer.catalog = Some(catalog);
                    self.events.push(Event::ListChanged);
                }
                vec![]
            }
            Message::GetReview { review_id } => self.serve_review(link, review_id, now_ms),
            Message::Review {
                review,
                photo,
                told_count,
            } => {
                let user = l.peer.expect("met");
                self.on_review(user, *review, photo, told_count, now_ms)
            }
            Message::NotFound { review_id } => {
                let user = l.peer.expect("met");
                if let Some(c) = self.peers.get_mut(&user).and_then(|p| p.catalog.as_mut()) {
                    c.entries.retain(|e| e.review_id != review_id);
                    self.events.push(Event::ListChanged);
                }
                if self
                    .pending
                    .get(&review_id)
                    .is_some_and(|p| p.asking.is_some_and(|(u, _)| u == user))
                {
                    self.advance(review_id, now_ms)
                } else {
                    vec![]
                }
            }
            Message::TradeHello => self.on_trade_hello(link, now_ms),
            Message::TradeOffer { card, at } => self.on_trade_offer(link, *card, at),
            Message::TradeConfirm(sig) => self.on_trade_confirm(link, sig),
            Message::TradeCancel => {
                if l.trade.take().is_some() {
                    self.events.push(Event::TradeCancelled { link });
                }
                vec![]
            }
            Message::Bye => {
                self.link_closed(link);
                vec![Action::Close {
                    link,
                    ignore_token_secs: 0,
                }]
            }
        }
    }

    fn on_met(&mut self, link: LinkId, met: Met) -> Vec<Action> {
        let user = met.certificate.user_id;
        let l = self.links.get_mut(&link).expect("link");
        l.peer = Some(user);
        let token = l.token;
        let peer = self.peers.entry(user).or_insert_with(|| Peer {
            cert: met.certificate.clone(),
            tokens: BTreeSet::new(),
            link: None,
            catalog: None,
            ignored: false,
            browse_only: false,
            served: VecDeque::new(),
            queued: Vec::new(),
        });
        peer.cert = met.certificate.clone();
        peer.tokens.insert(token);
        peer.link = Some(link);
        peer.browse_only = met.browse_only;
        self.events.push(Event::PeerMet {
            user_id: user,
            real_name: met.certificate.real_name.clone(),
            browse_only: met.browse_only,
        });
        let mut out = Vec::new();
        let held = peer.catalog.as_ref().map(|c| c.version);
        if !peer.ignored && !peer.browse_only && held != Some(met.catalog_version) {
            out.push(send(
                link,
                &Message::GetCatalog {
                    have_version: held.unwrap_or(0),
                },
            ));
        }
        for m in peer.queued.drain(..) {
            out.push(send(link, &m));
        }
        out
    }

    // ------------------------------------------------------------ sharing

    fn serve_review(&mut self, link: LinkId, review_id: Hash, now_ms: u64) -> Vec<Action> {
        let can_share = self.active_identity(secs(now_ms)).is_ok();
        let user = self.links[&link].peer.expect("met");
        let peer = self.peers.get_mut(&user).expect("peer");
        while peer.served.front().is_some_and(|t| now_ms >= t + 60_000) {
            peer.served.pop_front();
        }
        if peer.served.len() >= GET_REVIEW_PER_MINUTE {
            // Over the limit: no answer; they will try another holder.
            return vec![];
        }
        peer.served.push_back(now_ms);
        let reply = match self.store.saved_review(&review_id) {
            Some(s) if can_share => Message::Review {
                review: Box::new(s.review.clone()),
                photo: s.photo.clone(),
                told_count: s.sharer_told_count(),
            },
            _ => Message::NotFound { review_id },
        };
        vec![send(link, &reply)]
    }

    /// The list to show, built from everyone nearby. Pass my location if
    /// the phone has a fix.
    pub fn list(&self, location: Option<GeoPoint>) -> Vec<ListRow> {
        let offers: Vec<Offer<'_>> = self
            .peers
            .values()
            .filter(|p| !p.ignored && !p.browse_only)
            .filter_map(|p| {
                p.catalog.as_ref().map(|c| Offer {
                    holder: p.cert.user_id,
                    entries: &c.entries,
                })
            })
            .collect();
        let saved = self.store.saved_ids();
        build_list(
            &offers,
            &ListInputs {
                location,
                range_m: self.store.range_m,
                saved: &saved,
                blocked_users: &self.store.blocked_users,
                blocked_reviewers: &self.store.blocked_reviewers,
            },
        )
    }

    /// Tapped an entry: asks one holder for the full review.
    pub fn open_review(&mut self, review_id: Hash, now_ms: u64) -> Vec<Action> {
        if self.opened.contains_key(&review_id) {
            self.events.push(Event::ReviewOpened { review_id });
            return vec![];
        }
        if self.pending.contains_key(&review_id) {
            return vec![];
        }
        self.pending.insert(
            review_id,
            Pending {
                tried: BTreeSet::new(),
                asking: None,
            },
        );
        self.advance(review_id, now_ms)
    }

    /// Asks the next holder that has not been tried, or gives up.
    fn advance(&mut self, review_id: Hash, now_ms: u64) -> Vec<Action> {
        let Some(p) = self.pending.get_mut(&review_id) else {
            return vec![];
        };
        if let Some((u, _)) = p.asking.take() {
            p.tried.insert(u);
        }
        let next = self.peers.iter().find(|(u, peer)| {
            !p.tried.contains(*u)
                && !peer.ignored
                && !peer.browse_only
                && !peer.tokens.is_empty()
                && peer
                    .catalog
                    .as_ref()
                    .is_some_and(|c| c.entries.iter().any(|e| e.review_id == review_id))
        });
        let Some((&user, _)) = next else {
            self.pending.remove(&review_id);
            self.events.push(Event::ReviewUnavailable { review_id });
            return vec![];
        };
        p.asking = Some((user, now_ms));
        let msg = Message::GetReview { review_id };
        let link = self.peers[&user].link.filter(|l| self.is_met(*l));
        let peer = self.peers.get_mut(&user).unwrap();
        match link {
            Some(link) => vec![send(link, &msg)],
            None => {
                peer.queued.push(msg);
                let token = *peer.tokens.iter().next().unwrap();
                vec![Action::Connect { token }]
            }
        }
    }

    fn on_review(
        &mut self,
        sharer: UserId,
        review: Review,
        photo: Option<Vec<u8>>,
        told_count: u16,
        now_ms: u64,
    ) -> Vec<Action> {
        let review_id = review.review_id;
        let asked = self
            .pending
            .get(&review_id)
            .is_some_and(|p| p.asking.is_some_and(|(u, _)| u == sharer));
        if !asked {
            // Not something I asked this person for.
            return vec![];
        }
        let peer = &self.peers[&sharer];
        let claimed = peer
            .catalog
            .as_ref()
            .and_then(|c| c.entries.iter().find(|e| e.review_id == review_id));
        let check =
            verify_review(&review, photo.as_deref(), &self.trust, secs(now_ms)).and_then(|_| {
                if self
                    .store
                    .blocked_users
                    .contains(&review.body.reviewer.user_id)
                {
                    return Err(Error::Blocked);
                }
                check_entry(claimed.ok_or(Error::EntryMismatch("review id"))?, &review)
            });
        match check {
            Ok(()) => {
                self.pending.remove(&review_id);
                self.opened.insert(
                    review_id,
                    OpenedReview {
                        review,
                        photo,
                        sharer,
                        sharer_name: peer.cert.real_name.clone(),
                        sharer_told_count: told_count,
                    },
                );
                self.events.push(Event::ReviewOpened { review_id });
                vec![]
            }
            Err(reason) => {
                self.ignore_sharer(sharer, reason);
                self.advance(review_id, now_ms)
            }
        }
    }

    fn ignore_sharer(&mut self, user: UserId, reason: Error) {
        if let Some(peer) = self.peers.get_mut(&user) {
            peer.ignored = true;
            peer.catalog = None;
        }
        self.events.push(Event::SharerIgnored {
            user_id: user,
            reason,
        });
        self.events.push(Event::ListChanged);
    }

    pub fn opened(&self, review_id: &Hash) -> Option<&OpenedReview> {
        self.opened.get(review_id)
    }

    /// Closed without saving: the full review is deleted.
    pub fn close_review(&mut self, review_id: &Hash) {
        self.opened.remove(review_id);
    }

    /// Saves an opened review with its told-by note.
    pub fn save_review(&mut self, review_id: &Hash, now_ms: u64) -> Result<(), Error> {
        let now = secs(now_ms);
        self.active_identity(now)?;
        let o = self.opened.get(review_id).ok_or(Error::NotFound)?;
        let saved = SavedReview {
            review: o.review.clone(),
            photo: o.photo.clone(),
            told: Some(ToldBy {
                told_count: o.sharer_told_count.saturating_add(1),
                teller_id: o.sharer,
                teller_name: o.sharer_name.clone(),
                told_at: now,
            }),
            saved_at: now,
        };
        self.store.put_saved(saved)?;
        self.opened.remove(review_id);
        self.events.push(Event::ListChanged);
        Ok(())
    }

    pub fn delete_review(&mut self, review_id: &Hash) -> bool {
        let removed = self.store.delete_saved(review_id);
        if removed {
            self.events.push(Event::ListChanged);
        }
        removed
    }

    /// Blocks a person: their lists and reviews disappear and any link to
    /// them closes.
    pub fn block(&mut self, user: UserId) -> Vec<Action> {
        let mut reviewer_ids: BTreeSet<_> = self
            .store
            .saved()
            .filter(|s| s.review.body.reviewer.user_id == user)
            .map(|s| s.review.body.reviewer.reviewer_id())
            .collect();
        let mut out = Vec::new();
        if let Some(peer) = self.peers.remove(&user) {
            reviewer_ids.insert(peer.cert.reviewer_id());
            if let Some(link) = peer.link {
                out.push(send(link, &Message::Bye));
                out.push(Action::Close {
                    link,
                    ignore_token_secs: 0,
                });
                self.links.remove(&link);
            }
        }
        self.store.block(user, reviewer_ids);
        self.events.push(Event::ListChanged);
        out
    }

    /// Installs a newer revocation list from the server. Saved reviews by
    /// revoked people are dropped; returns how many.
    pub fn update_revocations(
        &mut self,
        list: crate::model::RevocationList,
        now_ms: u64,
    ) -> Result<usize, Error> {
        if !self.trust.update_revocations(list)? {
            return Ok(0);
        }
        let dropped = self.store.drop_revoked(&self.trust);
        let now = secs(now_ms);
        let revoked: Vec<UserId> = self
            .peers
            .values()
            .filter(|p| self.trust.is_revoked(&p.cert, now))
            .map(|p| p.cert.user_id)
            .collect();
        for u in revoked {
            self.ignore_sharer(u, Error::Revoked);
        }
        self.events.push(Event::ListChanged);
        Ok(dropped)
    }

    // ------------------------------------------------------------ trading

    fn trade_terms(&self, link: LinkId, now_ms: u64) -> Result<Trade, Error> {
        let me = self.active_identity(secs(now_ms))?.user_id;
        let l = self.links.get(&link).ok_or(Error::NotFound)?;
        let met = l.handshake.met().ok_or(Error::Protocol("not met"))?;
        if met.browse_only {
            return Err(Error::Trade("their certificate has expired"));
        }
        Ok(Trade::new(
            met.meeting_id,
            me,
            met.certificate.user_id,
            met.certificate.device_key,
        ))
    }

    pub fn trade_start(&mut self, link: LinkId, now_ms: u64) -> Result<Vec<Action>, Error> {
        let trade = self.trade_terms(link, now_ms)?;
        self.links.get_mut(&link).unwrap().trade = Some(trade);
        Ok(vec![send(link, &Message::TradeHello)])
    }

    fn on_trade_hello(&mut self, link: LinkId, now_ms: u64) -> Vec<Action> {
        match self.trade_terms(link, now_ms) {
            Ok(trade) => {
                let l = self.links.get_mut(&link).unwrap();
                if l.trade.is_none() {
                    l.trade = Some(trade);
                }
                self.events.push(Event::TradeStarted { link });
                vec![]
            }
            Err(_) => vec![send(link, &Message::TradeCancel)],
        }
    }

    pub fn trade_offer(
        &mut self,
        link: LinkId,
        card_id: &Hash,
        now_ms: u64,
    ) -> Result<Vec<Action>, Error> {
        let card = self.store.card(card_id).ok_or(Error::NotFound)?.clone();
        let trade = self
            .links
            .get_mut(&link)
            .and_then(|l| l.trade.as_mut())
            .ok_or(Error::Trade("no trade open"))?;
        let msg = trade.offer(card, secs(now_ms));
        Ok(vec![send(link, &msg)])
    }

    fn on_trade_offer(&mut self, link: LinkId, card: Card, at: Time) -> Vec<Action> {
        let l = self.links.get_mut(&link).unwrap();
        let Some(trade) = l.trade.as_mut() else {
            return vec![send(link, &Message::TradeCancel)];
        };
        match trade.on_offer(card.clone(), at) {
            Ok(()) => {
                self.events.push(Event::TradeOffered { link, card });
                vec![]
            }
            Err(_) => {
                l.trade = None;
                self.events.push(Event::TradeCancelled { link });
                vec![send(link, &Message::TradeCancel)]
            }
        }
    }

    pub fn trade_confirm(&mut self, link: LinkId) -> Result<Vec<Action>, Error> {
        let trade = self
            .links
            .get_mut(&link)
            .and_then(|l| l.trade.as_mut())
            .ok_or(Error::Trade("no trade open"))?;
        let msg = trade.confirm(&*self.signer)?;
        let out = vec![send(link, &msg)];
        self.try_finish(link);
        Ok(out)
    }

    fn on_trade_confirm(&mut self, link: LinkId, sig: crate::crypto::Signature) -> Vec<Action> {
        let Some(trade) = self.links.get_mut(&link).and_then(|l| l.trade.as_mut()) else {
            return vec![];
        };
        // A confirm for an older offer does not verify; it is dropped.
        if trade.on_confirm(sig).is_ok() {
            self.events.push(Event::TradePeerConfirmed { link });
            self.try_finish(link);
        }
        vec![]
    }

    fn try_finish(&mut self, link: LinkId) {
        let l = self.links.get_mut(&link).unwrap();
        let Some((record, mine, theirs)) = l.trade.as_ref().and_then(|t| t.finished()) else {
            return;
        };
        let (mine_id, mut theirs) = (mine.card_id, theirs.clone());
        l.trade = None;
        if self.store.cards.remove(&mine_id).is_none() {
            self.events.push(Event::TradeCancelled { link });
            return;
        }
        theirs.history.push(record.clone());
        self.store.cards.insert(theirs.card_id, theirs);
        self.events.push(Event::TradeCompleted { link, record });
    }

    pub fn trade_cancel(&mut self, link: LinkId) -> Vec<Action> {
        match self.links.get_mut(&link).and_then(|l| l.trade.take()) {
            Some(_) => vec![send(link, &Message::TradeCancel)],
            None => vec![],
        }
    }

    /// The trade on a link, for the screens.
    pub fn trade(&self, link: LinkId) -> Option<&Trade> {
        self.links.get(&link).and_then(|l| l.trade.as_ref())
    }
}
