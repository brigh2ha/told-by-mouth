# Decisions

Decisions Byung has made so far, newest first. The full reasoning is in [plan.md](plan.md).

| Date | Decision |
| --- | --- |
| 2026-10-30 | **Coding starts, at Byung's request**, following the review sharing algorithm spec (rev 44, https://claude.ai/artifact/5mNvvsPuEomyj8u6aQ4Hyt). First pieces: the shared Rust core `tbm_core` (every rule, no I/O, tested with multi-phone simulations) and the small server `tbm_server` (certificates, visit stamps, revocation list; stores no reviews). Crates use the `tbm_` prefix. |
| 2026-10-29 | The app is named **Told by Mouth**. "Mouth to mouth" was dropped because English speakers hear CPR. The new name plays on 구전동화 (folk tales passed on by word of mouth). |
| 2026-10-29 | The project moves to GitHub (`brigh2ha/told-by-mouth`). Only the planning material for Told by Mouth goes in. The old creature-game prototype code ("preflop") stays out. |
| 2026-10-25 | The goal changes from a creature-trading game to a **real-world restaurant collection and review app** for iOS and Android. |
| 2026-10-25 | You collect a restaurant by photographing its food there with the in-app camera (no gallery uploads), checked against your location. |
| 2026-10-25 | Reviews use **real names** and are shared **only face to face**, phone to phone, to fight fake reviews. They are signed, and each pass adds a "told by" signature. |
| 2026-10-25 | **Native screens**: SwiftUI on iPhone, Jetpack Compose on Android, for native feel, animations and design. A **shared Rust core** (via UniFFI) holds every rule. Bevy, Tauri + Leptos and Dioxus were rejected. |
| 2026-10-25 | **Mobile only.** There is no desktop app. Two-player behaviour is tested with Rust simulations. |
| 2026-10-25 | **Bluetooth LE only** for nearby play, written natively in Swift and Kotlin. **No QR codes.** Multipeer (Apple-only) and Wi-Fi Direct (Android-only) were rejected. |
| 2026-10-25 | Face-to-face play is trading and other friendly exchanges. **No battles.** |
| 2026-10-25 | **No code until Byung explicitly asks.** Planning and docs only for now. |
| 2026-10-25 | A small server is used for identity checks only. It stores no reviews. |

## Still open

- Which country first (decides the map service and the identity check provider).
- Does a trade swap cards, or give each player a copy? The competitor research leans towards a copy plus a scarce "first-hand" badge.
- How far does a review travel: only to people the reviewer meets, or onward through several people?
- How can a review be taken back once shared? (A "withdrawn" notice that spreads the same way?)
- Legal check on real-name reviews (defamation and privacy, especially in Korea) before launch.
- Whether to hold the line on in-person-only trading as players ask for remote trades.
