# Competitors for Mouth to Mouth to Mouth

Research from Oct 29, 2026. Original doc: https://claude.ai/artifact/UMMsgyzoVyCcjkfpemQUYA

> Written while the app was still called "Mouth to Mouth to Mouth" (M3). It is now **Told by Mouth**; read M3 below as Told by Mouth.

No app combines the three things Mouth to Mouth to Mouth (M3) does: proof of visit by food photo, restaurants you can trade, and reviews shared only face to face under real names. The biggest rival is **Beli**, a fast-growing restaurant ranking app. The closest mechanic is a tiny Android app called **ate**, and the closest trust idea is **Naver's receipt reviews** in Korea. The biggest risk is that in-person-only sharing spreads slowly.

M3 is short for Mouth to Mouth to Mouth below.

## Food and restaurant collection apps

Beli is the closest and strongest rival: it already turns eating out into a personal collection that friends compare. None of these apps ties the collection to a photo taken at the table, and none has trading.

| App | What it does well | How Mouth to Mouth to Mouth differs |
| --- | --- | --- |
| [Beli](https://www.bostonglobe.com/2026/08/04/lifestyle/beli-restaurant-rating-app/) | Rank-against-your-own-list rating that feels fun; 120M+ ratings across \~2M restaurants; you only see people you follow, which it pitches as more trustworthy | Beli takes your word that you ate there. M3 needs a photo of your food at the place, so every entry is proof of a visit. Beli shares online; M3 shares only in person, with trading |
| [ate, collect what you eat](https://play.google.com/store/apps/details?id=app.ate) | Closest mechanic: snap a plate, AI cuts out the dish as a sticker card, passport stamps per cuisine, pins for themed sets | Collects dishes, not restaurants; private diary with no trading, no reviews, no social layer. Tiny (50+ downloads), so it shows the idea works but nobody owns it yet |
| [Swarm (Foursquare)](https://en.wikipedia.org/wiki/Foursquare_Swarm) | The original "collect places" game: check-ins, stickers, mayorships, a lifelog of everywhere you went. Absorbed Foursquare City Guide after its 2024 shutdown | A check-in is a tap and easy to fake from nearby. M3 asks for a food photo, focuses only on restaurants, and adds trades and face-to-face reviews |
| [Mapstr](https://apps.apple.com/us/app/id917288465?l=en-us) | Clean personal map of saved places with tags, "To try" and "Tried", merging maps of friends and creators; no ads | A bookmarking tool, not a game. No proof of visit, no collecting goal, no trading |
| Yelp and Google Maps | Huge coverage, opening hours, photos and millions of reviews; the default way people pick a restaurant | Anonymous public reviews that anyone can post, which is exactly the fake-review problem M3 sets out to avoid. M3 is not a search engine and should not try to be one |

M3 will still lean on a map provider (Google, Apple, Naver or Kakao) to look up which restaurant a photo was taken in, so Google Maps is both a rival and a supplier.

## Location-based collecting games

These games prove people will walk somewhere real to collect something and will trade with people they meet. Their collectibles are invented, though; M3 collects real restaurants, which is both its hook and its limit, because you cannot spawn more.

| Game | What it does well | How Mouth to Mouth to Mouth differs |
| --- | --- | --- |
| Pokémon Go | The model for "go somewhere, collect, trade". Trades used to require players to stand close together, which made meetups part of the game. In December 2025 it added [remote trades](https://pokemongo.com/en/news/pgo-remote-trade-2025), but only for "Forever Friends", one at a time, and with long lists of what cannot be traded | Pokémon Go is now loosening in-person rules after years of player requests. M3 keeps trading strictly face to face over Bluetooth. That fits the trust story but limits how often trades happen, so M3 needs other reasons to meet |
| [Pikmin Bloom](https://www.pocketgamer.com/pikmin-bloom/postcard-day) | Collectible postcards based on real landmarks near you; calm, walking-focused play without battles | Postcards are tied to a place but not to proof you did anything there. M3's food photo is the proof, and the collectible is the restaurant itself |
| Swarm stickers and mayorships | Turned real visits into badges and friendly competition years before Beli | Already covered above; the lesson is that badges alone faded once novelty wore off, so M3's trades and reviews need to give a lasting reason to keep collecting |

One design lesson from Pokémon Go: limits on trading (cooldowns, one trade per friend, items that can't be traded) are what keep a trade economy interesting. M3 still has the open question of whether a trade is a swap or a copy, and this research leans towards copy plus a scarce "first-hand" badge, because only the original visitor actually ate there.

## Apps that try to make reviews trustworthy

Everyone big fights fake reviews after they are posted, by filtering and deleting. M3 fights them before they exist, by making a review something a real person hands you in person.

| Approach | What it does well | How Mouth to Mouth to Mouth differs |
| --- | --- | --- |
| [Yelp filtering](https://www.businesswire.com/news/home/20260225039344/en/Yelp-Releases-2025-Trust-Safety-Report/) | Of about 22M reviews in 2025, \~17% were hidden as "not recommended" and \~11% removed; \~500K looked AI-written and 1.3M accounts were closed | Shows the scale of the problem: even after all that, readers still don't know the reviewer. M3 reviews come with a real name and a face you met |
| [Naver receipt reviews](https://www.asiae.co.kr/en/article/2020082808123325189) (Korea) | Proof of purchase: you scan a receipt before you can review. Passed 100M receipt reviews, around 400K a day | Closest idea to M3's photo proof. Still public and pseudonymous, and receipts can be borrowed. M3 adds a real name and in-person sharing. If Byung launches in Korea, this is the bar users will compare against |
| [Beli's follow-only feed](https://www.bostonglobe.com/2026/08/04/lifestyle/beli-restaurant-rating-app/) | You only see ratings from people you chose to follow, so strangers can't flood your feed | Trust comes from the social graph, but it still spreads online and nothing proves the visit. M3 requires both proof and a meeting |
| Law: the [US FTC fake-review rule](https://wsgr.com/en/insights/ftc-issues-final-rule-banning-fake-and-misleading-consumer-reviews-and-testimonials.html) | Since 21 October 2024, buying or selling fake reviews can cost nearly $52,000 per violation | Regulators are pushing the same way M3 is. The flip side: real-name negative reviews raise defamation risk (for example in Korea), which is already on M3's open-questions list |

## Apps with nearby or in-person trading

Nobody does in-person trading for restaurants. The closest examples are games and phone features, and they show that nearby exchange is loved when it is effortless and dies when it needs both people to fiddle with their phones.

| Product | What it does well | How Mouth to Mouth to Mouth differs |
| --- | --- | --- |
| [Nintendo StreetPass](https://en-americas-support.nintendo.com/app/answers/detail/a_id/404/~/streetpass-feature-overview) (3DS) | Swapped data automatically with strangers you walked past, even in sleep mode; fans still miss it and hobby projects keep trying to revive it | Passive and anonymous. M3 is deliberate and named: you choose to trade with someone you are actually talking to. A passive "you passed another M3 player" moment could still be a fun extra |
| Pokémon Go trading | In-person trades made meetups and community days social events | Its move to remote trades in 2025 shows the pressure M3 will face from players who live far from friends. M3 should decide early whether to hold the line |
| Apple NameDrop and AirDrop, and the old Bump app (memory, not looked up) | Hold two phones together to swap contacts or files; proved the gesture feels magical | Not games and carry no trust. iOS limits background Bluetooth, which is why NameDrop is Apple-only. M3's trade screen must be open in the foreground on both phones, so the flow has to be quick |

The practical takeaway is that the trade moment is M3's signature interaction. It should take seconds, feel physical (phones close together, a satisfying animation), and work between an iPhone and an Android phone, which the Apple-only features cannot.

## Gaps M3 could fill, and risks

**Gaps no one fills today**

1. **Proof you actually ate there.** Beli, Mapstr, Swarm and Yelp trust your word. Only Naver asks for a receipt. A food photo with location, taken in the app, is a lighter and more fun proof.
2. **Reviews from someone you have met.** Every competitor spreads reviews online, to strangers or followers. A real-name review handed over in person, with a "told by" chain, does not exist anywhere.
3. **Restaurants as tradeable collectibles.** ate collects dishes and Beli collects rankings, but nobody lets you trade a restaurant to a friend. This turns "you have to try this place" into a game move.
4. **A food game without battles.** Location games lean on fighting or step counting. A calm, social collecting game about eating out is open space.

**Risks to plan for**

- **Beli is moving fast** with Gen Z and could add photo proof or in-person features. M3's moat is the face-to-face rule, so keep it strict.
- **Slow spread.** In-person-only sharing grows only as fast as people meet. Pokémon Go eventually gave in and allowed remote trades.
- **Few people to trade with at launch.** A trade needs two players in the same place. Launching in one city or campus first would help.
- **Defamation and privacy** from real-name reviews, already an open question.
- **Map data dependence** on Google, Apple, Naver or Kakao to identify the restaurant from a photo's location.
