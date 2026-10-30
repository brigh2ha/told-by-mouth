//! Told by Mouth shared core.
//!
//! Every rule of the app lives here so the iPhone and Android apps can never
//! disagree: writing and checking reviews, signatures, building the nearby
//! list, the meeting handshake, the message protocol and card trades. The
//! crate does no I/O. The native apps drive the camera, location, Bluetooth
//! radio and secure chip, and pass bytes and events in and out.

pub mod advert;
pub mod cbor;
pub mod collect;
pub mod crypto;
pub mod error;
pub mod geo;
pub mod limits;
pub mod list;
pub mod meeting;
pub mod model;
pub mod node;
pub mod review;
pub mod store;
pub mod trade;
pub mod trust;
pub mod wire;

#[cfg(any(test, feature = "testkit"))]
pub mod testkit;

pub use error::Error;
pub use node::{Action, Event, LinkId, Node};
