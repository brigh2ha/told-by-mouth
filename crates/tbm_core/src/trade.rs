//! Trading a card (spec section 9): each picks a card, both confirm with a
//! signature over the same Trade record, then the cards swap.

use crate::crypto::{PublicKey, Signature, Signer};
use crate::error::Error;
use crate::limits::Time;
use crate::model::{Card, MeetingId, TradeRecord, UserId};
use crate::wire::Message;

#[derive(Clone, Debug)]
pub struct Trade {
    meeting_id: MeetingId,
    me: UserId,
    them: UserId,
    their_key: PublicKey,
    mine: Option<(Card, Time)>,
    theirs: Option<(Card, Time)>,
    my_sig: Option<Signature>,
    their_sig: Option<Signature>,
}

/// The unsigned parts of the record, the same on both phones.
struct Terms {
    user_a: UserId,
    user_b: UserId,
    card_a: [u8; 32],
    card_b: [u8; 32],
    at: Time,
}

impl Terms {
    fn bytes(&self, meeting_id: &MeetingId) -> Vec<u8> {
        TradeRecord::signed_bytes(
            meeting_id,
            &self.user_a,
            &self.user_b,
            &self.card_a,
            &self.card_b,
            self.at,
        )
    }
}

pub fn check_card(card: &Card) -> Result<(), Error> {
    if card.card_id != Card::id_for(&card.origin_visit) {
        return Err(Error::IdMismatch("card"));
    }
    crate::collect::check_place(&card.place)
}

impl Trade {
    pub fn new(meeting_id: MeetingId, me: UserId, them: UserId, their_key: PublicKey) -> Self {
        Self {
            meeting_id,
            me,
            them,
            their_key,
            mine: None,
            theirs: None,
            my_sig: None,
            their_sig: None,
        }
    }

    pub fn my_offer(&self) -> Option<&Card> {
        self.mine.as_ref().map(|(c, _)| c)
    }

    pub fn their_offer(&self) -> Option<&Card> {
        self.theirs.as_ref().map(|(c, _)| c)
    }

    pub fn they_confirmed(&self) -> bool {
        self.their_sig.is_some()
    }

    pub fn i_confirmed(&self) -> bool {
        self.my_sig.is_some()
    }

    /// Picks (or changes) my card. Changing an offer clears both confirms.
    pub fn offer(&mut self, card: Card, at: Time) -> Message {
        self.mine = Some((card.clone(), at));
        self.my_sig = None;
        self.their_sig = None;
        Message::TradeOffer {
            card: Box::new(card),
            at,
        }
    }

    /// Their card (or a changed one). Clears both confirms.
    pub fn on_offer(&mut self, card: Card, at: Time) -> Result<(), Error> {
        check_card(&card)?;
        if self
            .mine
            .as_ref()
            .is_some_and(|(m, _)| m.card_id == card.card_id)
        {
            return Err(Error::Trade("both offered the same card"));
        }
        self.theirs = Some((card, at));
        self.my_sig = None;
        self.their_sig = None;
        Ok(())
    }

    fn terms(&self) -> Result<Terms, Error> {
        let (Some((mine, my_at)), Some((theirs, their_at))) = (&self.mine, &self.theirs) else {
            return Err(Error::Trade("both must offer a card first"));
        };
        let at = (*my_at).max(*their_at);
        Ok(if self.me < self.them {
            Terms {
                user_a: self.me,
                user_b: self.them,
                card_a: mine.card_id,
                card_b: theirs.card_id,
                at,
            }
        } else {
            Terms {
                user_a: self.them,
                user_b: self.me,
                card_a: theirs.card_id,
                card_b: mine.card_id,
                at,
            }
        })
    }

    /// Signs the record and returns TRADE_CONFIRM.
    pub fn confirm(&mut self, signer: &dyn Signer) -> Result<Message, Error> {
        let terms = self.terms()?;
        let sig = signer.sign(&terms.bytes(&self.meeting_id))?;
        self.my_sig = Some(sig);
        Ok(Message::TradeConfirm(sig))
    }

    /// Their signature. A signature over an older offer (crossed in flight)
    /// does not verify and is refused; they will confirm again.
    pub fn on_confirm(&mut self, sig: Signature) -> Result<(), Error> {
        let terms = self.terms()?;
        self.their_key
            .verify(&terms.bytes(&self.meeting_id), &sig, "trade")?;
        self.their_sig = Some(sig);
        Ok(())
    }

    /// With both signatures: the finished record, my card and theirs.
    pub fn finished(&self) -> Option<(TradeRecord, &Card, &Card)> {
        let (my_sig, their_sig) = (self.my_sig?, self.their_sig?);
        let terms = self.terms().ok()?;
        let (sig_a, sig_b) = if self.me < self.them {
            (my_sig, their_sig)
        } else {
            (their_sig, my_sig)
        };
        let record = TradeRecord {
            meeting_id: self.meeting_id,
            user_a: terms.user_a,
            user_b: terms.user_b,
            card_a: terms.card_a,
            card_b: terms.card_b,
            at: terms.at,
            sig_a,
            sig_b,
        };
        Some((record, &self.mine.as_ref()?.0, &self.theirs.as_ref()?.0))
    }
}

/// Checks both signatures of a finished record.
pub fn verify_record(
    record: &TradeRecord,
    key_a: &PublicKey,
    key_b: &PublicKey,
) -> Result<(), Error> {
    let bytes = TradeRecord::signed_bytes(
        &record.meeting_id,
        &record.user_a,
        &record.user_b,
        &record.card_a,
        &record.card_b,
        record.at,
    );
    key_a.verify(&bytes, &record.sig_a, "trade")?;
    key_b.verify(&bytes, &record.sig_b, "trade")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::*;

    fn sig(m: Message) -> Signature {
        match m {
            Message::TradeConfirm(s) => s,
            _ => panic!(),
        }
    }

    #[test]
    fn swap_with_two_way_confirm() {
        let w = World::new();
        let (kim, lee) = (w.person("Kim"), w.person("Lee"));
        let kc = Card::from_visit(&kim.visit(&w, gangnam(), T0));
        let lc =
            Card::from_visit(&lee.visit(&w, place("kakao:9", "Alley Dumplings", 37.5, 127.0), T0));
        let mid = [3; 16];
        let mut a = Trade::new(mid, kim.user_id(), lee.user_id(), lee.cert.device_key);
        let mut b = Trade::new(mid, lee.user_id(), kim.user_id(), kim.cert.device_key);

        assert!(a.confirm(&*kim.key).is_err());
        a.offer(kc.clone(), T0);
        b.on_offer(kc.clone(), T0).unwrap();
        b.offer(lc.clone(), T0 + 5);
        a.on_offer(lc.clone(), T0 + 5).unwrap();

        let sa = sig(a.confirm(&*kim.key).unwrap());
        b.on_confirm(sa).unwrap();
        assert!(b.finished().is_none());

        // Lee changes their mind: both confirms clear, and Kim's old
        // signature no longer fits.
        let lc2 =
            Card::from_visit(&lee.visit(&w, place("kakao:10", "Bibim Bar", 37.51, 127.01), T0));
        b.offer(lc2.clone(), T0 + 9);
        a.on_offer(lc2.clone(), T0 + 9).unwrap();
        assert!(!a.i_confirmed() && !b.they_confirmed());
        assert!(b.on_confirm(sa).is_err());

        let sa = sig(a.confirm(&*kim.key).unwrap());
        let sb = sig(b.confirm(&*lee.key).unwrap());
        b.on_confirm(sa).unwrap();
        a.on_confirm(sb).unwrap();
        let (ra, mine_a, theirs_a) = a.finished().unwrap();
        let (rb, _, _) = b.finished().unwrap();
        assert_eq!(ra, rb);
        assert_eq!(mine_a, &kc);
        assert_eq!(theirs_a, &lc2);
        assert_eq!(ra.at, T0 + 9);
        let (ka, kb) = if kim.user_id() < lee.user_id() {
            (kim.cert.device_key, lee.cert.device_key)
        } else {
            (lee.cert.device_key, kim.cert.device_key)
        };
        verify_record(&ra, &ka, &kb).unwrap();
        assert!(verify_record(&ra, &kb, &ka).is_err());
    }

    #[test]
    fn rejects_bad_cards() {
        let w = World::new();
        let kim = w.person("Kim");
        let mut card = Card::from_visit(&kim.visit(&w, gangnam(), T0));
        let mut t = Trade::new([0; 16], [1; 16], [2; 16], kim.cert.device_key);
        card.card_id = [0; 32];
        assert_eq!(t.on_offer(card, T0), Err(Error::IdMismatch("card")));
    }
}
