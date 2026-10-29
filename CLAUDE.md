# Told by Mouth

Mobile app (iOS + Android) where people collect real restaurants by photographing their food there, trade restaurants face to face, and pass on real-name reviews only in person. See [README.md](README.md) and [docs/plan.md](docs/plan.md).

## Standing rules from Byung

- **No code until Byung explicitly asks.** Do not write, scaffold or commit source code (not even "just a skeleton") until Byung says to start coding. Planning, docs and answering questions are fine. Ending a plan with "should I start?" is fine; starting on an implied yes is not.
- **Mobile only.** iPhone and Android. No desktop app, no web app. Two-player behaviour is tested with Rust simulations, not a desktop window.
- **Bluetooth LE only** for nearby play. **Never propose QR codes.** Multipeer (Apple-only) and Wi-Fi Direct (Android-only) are out because an iPhone must be able to meet an Android phone.
- **No battles.** Face-to-face play is trading and other friendly exchanges.
- **Reviews are real-name and face to face only.** Never add a public feed, online review posting or remote review sharing.
- **Native screens with a shared Rust core.** SwiftUI on iOS, Jetpack Compose on Android, Rust core via UniFFI. Not Bevy, not Tauri, not Dioxus, not a web view. Byung cares a lot about native feel, animations and a cool design.
- **Screens hold no rules.** Every decision (can this be reviewed, is this signature valid, did the trade finish) lives in Rust so the two apps can never disagree.
- **The old creature game is gone.** This project started as a creature-trading game called "preflop". Its code is deliberately not in this repo; do not bring it back or design around creatures.

## Working with Byung

- Byung has a Mac and tests on real phones. iOS builds need the Mac; Bluetooth needs two real phones (simulators have no Bluetooth).
- Open product questions are listed in [docs/decisions.md](docs/decisions.md). Ask Byung rather than deciding them.
- Record new decisions in `docs/decisions.md` with the date.
