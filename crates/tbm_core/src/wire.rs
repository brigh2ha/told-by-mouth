//! Messages between two phones and their framing on the Bluetooth link.
//!
//! Each message is a type (1 byte), a length (3 bytes, big endian) and a
//! CBOR payload. The native Bluetooth code cuts frames into chunks of at
//! most 512 bytes and feeds received chunks to a [`FrameReader`].

use crate::cbor::{Dec, Enc};
use crate::crypto::{Hash, Signature};
use crate::error::Error;
use crate::limits::{Time, MAX_MESSAGE_BYTES, PHOTO_MAX_BYTES};
use crate::model::{Card, Catalog, Certificate, Review};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    pub protocol: u16,
    pub certificate: Certificate,
    pub nonce: [u8; 16],
    pub catalog_version: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Hello(Hello),
    /// Signature over "tbm/hello/1", the other's nonce and my own.
    Prove(Signature),
    /// The version I already have, or 0.
    GetCatalog {
        have_version: u32,
    },
    Catalog(Catalog),
    GetReview {
        review_id: Hash,
    },
    Review {
        review: Box<Review>,
        photo: Option<Vec<u8>>,
        /// 0 for a review the sharer wrote, otherwise the count in their note.
        told_count: u16,
    },
    /// Deleted since the list was sent (or never held).
    NotFound {
        review_id: Hash,
    },
    TradeHello,
    /// The card I give, and when I offered it.
    TradeOffer {
        card: Box<Card>,
        at: Time,
    },
    /// My signature over the trade record.
    TradeConfirm(Signature),
    TradeCancel,
    Bye,
}

mod kind {
    pub const HELLO: u8 = 0x01;
    pub const PROVE: u8 = 0x02;
    pub const GET_CATALOG: u8 = 0x10;
    pub const CATALOG: u8 = 0x11;
    pub const GET_REVIEW: u8 = 0x12;
    pub const REVIEW: u8 = 0x13;
    pub const NOT_FOUND: u8 = 0x14;
    pub const TRADE_HELLO: u8 = 0x20;
    pub const TRADE_OFFER: u8 = 0x21;
    pub const TRADE_CONFIRM: u8 = 0x22;
    pub const TRADE_CANCEL: u8 = 0x23;
    pub const BYE: u8 = 0x7f;
}

impl Message {
    fn kind(&self) -> u8 {
        match self {
            Message::Hello(_) => kind::HELLO,
            Message::Prove(_) => kind::PROVE,
            Message::GetCatalog { .. } => kind::GET_CATALOG,
            Message::Catalog(_) => kind::CATALOG,
            Message::GetReview { .. } => kind::GET_REVIEW,
            Message::Review { .. } => kind::REVIEW,
            Message::NotFound { .. } => kind::NOT_FOUND,
            Message::TradeHello => kind::TRADE_HELLO,
            Message::TradeOffer { .. } => kind::TRADE_OFFER,
            Message::TradeConfirm(_) => kind::TRADE_CONFIRM,
            Message::TradeCancel => kind::TRADE_CANCEL,
            Message::Bye => kind::BYE,
        }
    }

    fn payload(&self) -> Vec<u8> {
        let mut e = Enc::new();
        match self {
            Message::Hello(h) => {
                e.array(4)
                    .u64(h.protocol as u64)
                    .item(&h.certificate)
                    .bytes(&h.nonce)
                    .u64(h.catalog_version as u64);
            }
            Message::Prove(sig) | Message::TradeConfirm(sig) => {
                e.item(sig);
            }
            Message::GetCatalog { have_version } => {
                e.u64(*have_version as u64);
            }
            Message::Catalog(c) => {
                e.item(c);
            }
            Message::GetReview { review_id } | Message::NotFound { review_id } => {
                e.bytes(review_id);
            }
            Message::Review {
                review,
                photo,
                told_count,
            } => {
                e.array(3)
                    .item(review.as_ref())
                    .opt_bytes(photo.as_deref())
                    .u64(*told_count as u64);
            }
            Message::TradeOffer { card, at } => {
                e.array(2).item(card.as_ref()).u64(*at);
            }
            Message::TradeHello | Message::TradeCancel | Message::Bye => {
                e.null();
            }
        }
        e.finish()
    }

    /// The whole frame: type, 3-byte length, payload.
    pub fn to_frame(&self) -> Vec<u8> {
        let payload = self.payload();
        assert!(payload.len() <= MAX_MESSAGE_BYTES, "message too large");
        let len = payload.len() as u32;
        let mut out = Vec::with_capacity(4 + payload.len());
        out.push(self.kind());
        out.extend_from_slice(&len.to_be_bytes()[1..]);
        out.extend_from_slice(&payload);
        out
    }

    pub fn from_payload(kind: u8, payload: &[u8]) -> Result<Self, Error> {
        let mut d = Dec::new(payload);
        let msg = match kind {
            kind::HELLO => {
                d.expect_array(4)?;
                Message::Hello(Hello {
                    protocol: d.u16()?,
                    certificate: d.item()?,
                    nonce: d.fixed()?,
                    catalog_version: d.u32()?,
                })
            }
            kind::PROVE => Message::Prove(d.item()?),
            kind::GET_CATALOG => Message::GetCatalog {
                have_version: d.u32()?,
            },
            kind::CATALOG => Message::Catalog(d.item()?),
            kind::GET_REVIEW => Message::GetReview {
                review_id: d.fixed()?,
            },
            kind::REVIEW => {
                d.expect_array(3)?;
                let review = Box::new(d.item()?);
                let photo = d.opt_bytes()?.map(<[u8]>::to_vec);
                if photo.as_ref().is_some_and(|p| p.len() > PHOTO_MAX_BYTES) {
                    return Err(Error::PhotoTooLarge {
                        max: PHOTO_MAX_BYTES,
                    });
                }
                Message::Review {
                    review,
                    photo,
                    told_count: d.u16()?,
                }
            }
            kind::NOT_FOUND => Message::NotFound {
                review_id: d.fixed()?,
            },
            kind::TRADE_HELLO | kind::TRADE_CANCEL | kind::BYE => {
                if !d.null()? {
                    return Err(Error::Decode("expected null".into()));
                }
                match kind {
                    kind::TRADE_HELLO => Message::TradeHello,
                    kind::TRADE_CANCEL => Message::TradeCancel,
                    _ => Message::Bye,
                }
            }
            kind::TRADE_OFFER => {
                d.expect_array(2)?;
                Message::TradeOffer {
                    card: Box::new(d.item()?),
                    at: d.u64()?,
                }
            }
            kind::TRADE_CONFIRM => Message::TradeConfirm(d.item()?),
            _ => return Err(Error::Protocol("unknown message type")),
        };
        d.finish()?;
        Ok(msg)
    }
}

/// Cuts a frame into chunks that fit the link.
pub fn chunks(frame: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    frame
        .chunks(chunk_size.max(1))
        .map(<[u8]>::to_vec)
        .collect()
}

/// Reassembles messages from chunks received in order on one link.
#[derive(Default, Debug)]
pub struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds received bytes and returns every message now complete. An error
    /// means the link is broken and should be closed.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Message>, Error> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            if self.buf.len() < 4 {
                break;
            }
            let len = u32::from_be_bytes([0, self.buf[1], self.buf[2], self.buf[3]]) as usize;
            if len > MAX_MESSAGE_BYTES {
                return Err(Error::Protocol("message too large"));
            }
            if self.buf.len() < 4 + len {
                break;
            }
            let msg = Message::from_payload(self.buf[0], &self.buf[4..4 + len])?;
            self.buf.drain(..4 + len);
            out.push(msg);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::LINK_CHUNK;
    use crate::testkit::*;

    #[test]
    fn frames_round_trip_through_small_chunks() {
        let w = World::new();
        let kim = w.person("Kim Minji");
        let photo = vec![3u8; 3000];
        let review = kim.review(&w, gangnam(), T0, "Best cold noodles", Some(photo.clone()));
        let card = Card::from_visit(&review.body.visit);
        let msgs = vec![
            Message::Hello(Hello {
                protocol: 1,
                certificate: kim.cert.clone(),
                nonce: [4; 16],
                catalog_version: 77,
            }),
            Message::Prove(Signature([5; 64])),
            Message::GetCatalog { have_version: 0 },
            Message::Catalog(Catalog {
                version: 3,
                entries: vec![review.list_entry()],
            }),
            Message::GetReview {
                review_id: review.review_id,
            },
            Message::Review {
                review: Box::new(review.clone()),
                photo: Some(photo),
                told_count: 2,
            },
            Message::NotFound { review_id: [1; 32] },
            Message::TradeHello,
            Message::TradeOffer {
                card: Box::new(card),
                at: T0,
            },
            Message::TradeConfirm(Signature([6; 64])),
            Message::TradeCancel,
            Message::Bye,
        ];
        let mut stream = Vec::new();
        for m in &msgs {
            stream.extend(m.to_frame());
        }
        let mut reader = FrameReader::new();
        let mut got = Vec::new();
        for c in chunks(&stream, LINK_CHUNK) {
            assert!(c.len() <= LINK_CHUNK);
            got.extend(reader.push(&c).unwrap());
        }
        assert_eq!(got, msgs);
    }

    #[test]
    fn frame_header_layout() {
        let f = Message::GetCatalog { have_version: 300 }.to_frame();
        assert_eq!(f, vec![0x10, 0, 0, 3, 0x19, 0x01, 0x2c]);
    }

    #[test]
    fn rejects_garbage() {
        assert!(FrameReader::new().push(&[0x10, 0xff, 0xff, 0xff]).is_err());
        assert!(FrameReader::new().push(&[0x55, 0, 0, 1, 0xf6]).is_err());
        assert!(FrameReader::new()
            .push(&[0x10, 0, 0, 2, 0x01, 0x01])
            .is_err());
        // Incomplete is not an error yet.
        assert!(FrameReader::new()
            .push(&[0x10, 0, 0, 3, 0x19])
            .unwrap()
            .is_empty());
    }
}
