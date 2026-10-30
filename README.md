# Told by Mouth

A mobile app (iPhone and Android) for collecting real restaurants and passing on honest reviews, the old-fashioned way: by word of mouth.

- **Collect** a restaurant by photographing your food there with the in-app camera. Your location proves you were there.
- **Trade** restaurants with people you meet, phone to phone over Bluetooth.
- **Share reviews face to face only.** Every review carries the reviewer's verified real name and a digital signature, plus a "told by" chain showing who passed it to you. No public review site, so no fake reviews.

The name plays on 구전동화, folk tales handed down by mouth: one mouth eats, one mouth tells, another mouth eats.

## Status

Coding started on Oct 30, 2026, at Byung's request.

- `crates/tbm_core`: the shared Rust core. Every rule (reviews, signatures, the nearby list, the meeting handshake, messages, trades) as pure Rust with no I/O, tested with multi-phone simulations. Run `cargo test`.
- `crates/tbm_server`: the small server for certificates, visit stamps and the revocation list. It stores no reviews. See [docs/server.md](docs/server.md).

The iPhone and Android apps (and the UniFFI bridge) are not started yet.

## Planned stack

- Screens: SwiftUI (iOS) and Jetpack Compose (Android)
- Shared Rust core for every rule (cards, reviews, signatures, trading), bridged with UniFFI
- Bluetooth LE for nearby play, written in Swift and Kotlin
- A small identity server for one-time real-name checks

## Docs

- [docs/plan.md](docs/plan.md): how the app works, how it stops fake reviews, architecture and milestones
- [docs/decisions.md](docs/decisions.md): decisions made so far and open questions
- [docs/competitors.md](docs/competitors.md): competitor research (Beli, ate, Naver receipt reviews and more)
- [CLAUDE.md](CLAUDE.md): standing rules for anyone (or any Claude) working here
