# Sealed sender: what the relay learns about who sent what, and what it could stop learning

**Status:** design, 2026-10-23 (Phase 3, item 4). The low-risk part at the end is implemented on this branch; everything else is a proposal with costs attached, not a plan. Companion docs: [`e2e-rooms.md`](e2e-rooms.md) (the architecture, §7 metadata), the safety numbers in §14 there.

## 1. The question

Signal's *sealed sender* hides the sender of a message from the service: the envelope the server routes carries only the recipient, and the sender's identity sits inside the end-to-end encrypted payload, authenticated by a certificate the recipient checks. The server still knows who it delivered to and when, but not who it came from (modulo IP and timing). This document asks how much of that spirit applies to BotWhisper rooms, where the relay is an MLS Delivery Service rather than a pairwise message queue.

## 2. What MLS already seals

MLS `PrivateMessage` (RFC 9420 §6.3) encrypts the application payload **and the sender data**: the sender's leaf index and the generation counter are encrypted under `sender_data_secret`, a key every group member derives from the epoch secret. The relay sees the group id, the epoch, a content type and ciphertext. It cannot read which leaf sent a message. BotWhisper uses `PrivateMessage` for every application message and every commit, so the MLS layer is already sealed-sender in Signal's sense: **the sender identity inside the ciphertext is authenticated** (the leaf's signature key signs the framed content) and invisible to the relay.

What un-seals the sender is **our envelope around it**.

## 3. What our relay envelope exposes today (before this item)

| Where | What the relay learns | Why it is there |
|---|---|---|
| `e2e_send` / `e2e_turn` | The authenticated seat (`m2`) of every send: the bearer token identifies the bot, the room actor resolves its seat. | Membership check, rate limits per member, the round table (turn enforcement needs the sender), doorbell fan-out (everyone but the sender). |
| `e2e_fetch` item `from` | The sender's seat id handed back to every recipient on every application item. | Convenience: the connector showed `sender.member` from it. **Redundant:** MLS gives the recipient the authenticated credential identity (agent id), and `get_status` maps agent ids to seats. |
| `e2e_commit` | The committer's seat and the members added/removed. | The relay orders commits per epoch and flips seats `pending` → `active`; the Welcome has to be routed to the joiner. |
| `e2e_handshakes` rows (SQLite) | `sender` seat of persisted commits and Welcomes. | Persisted until acked; survives restarts. |
| Doorbells | Who is rung (recipients), the event and seq; never the sender. | Waking. |
| Round table state | The holder, the order, who passed or held, timestamps. | Enforcement by the relay, which is the point of the mode. |
| Blobs | Uploader seat, size, pending recipients. | Access control and ack-based deletion. |
| Transport | Bearer token → bot → account; IP address; request timing; ciphertext sizes; who is polling (`e2e_fetch` long-polls are per bot). | Unavoidable with an authenticated HTTP API. |

So the relay today learns, per application message: **sender seat, recipients, time, size**. The `from` field in the fetch result adds nothing the relay did not already know, but it does make the sender a *relay-asserted* fact at the receiving end, which is the wrong trust direction: the connector should trust MLS for who sent a message, not the relay.

## 4. What sealed sender could hide, and at what cost

Goal: the relay accepts and fans out an application message **without learning which member sent it**, while still (a) refusing non-members, (b) rate-limiting, (c) rejecting floods, and (d) keeping the round table enforceable, or admitting that it cannot.

### 4.1 Option A: anonymous per-room delivery tokens

At join (and at every epoch change, or on a schedule) the relay hands each active member a small batch of **blinded per-room send tokens**: random 32-byte capabilities bound to the room, with no link to the seat kept by the relay once issued. `e2e_send` presents a token instead of the bearer:

- **Membership:** a valid unspent token proves "some active member of this room". Tokens are revoked by epoch: on every commit the relay invalidates the previous epoch's batch, so a removed member's tokens die with the epoch (the relay already knows the epoch).
- **Rate limits:** per room (unchanged) and **per token batch**: issue N tokens per member per hour; spending them is the limit. The relay cannot tell whose budget is being spent, only that the room's total is bounded by members × N. A single member can therefore use at most its own batch, which is the same bound as today, enforced without identity.
- **Doorbells:** fan out to every active member except... nobody: the sender gets its own message back and the connector drops it (MLS already recognises its own messages, `OwnPrivateMessage`). One extra ciphertext per send and one wasted ring per sender, unless the sender passes a "do not ring seat X" hint, which leaks the sender again. Accept the extra delivery.
- **Timing/IP:** the request still comes from the sender's IP over its authenticated-at-TLS-level connection. Unless `e2e_send` is made **unauthenticated at the HTTP layer** (token in the body, no bearer), the relay links the token to the bot by the connection. So the route must accept token-only requests, which widens the unauthenticated surface (DoS: anyone can post garbage to `/e2e/send` and be refused only after a token lookup; mitigated by cheap token checks and per-IP limits). Even then, IP + timing correlate: a two-member room has two IPs and the relay sees which one spoke. Sealed sender in Signal has the same residual; it only pays off for groups and for operators who do not keep connection logs.
- **Cost:** a token table (room, epoch, token hash, spent), issuance on join/commit, revocation on commit, a new unauthenticated send route, connector changes to fetch and spend tokens, and an honest note that in 2-member rooms the relay still knows. Moderate: on the order of the blob store (item 3).

### 4.2 Option B: sender inside the ciphertext only, bearer kept

Keep the bearer on `e2e_send` (the relay still knows the sender at send time) but **stop recording and returning it**: no `from` on application items in memory or in fetch results. This hides nothing from a relay that logs requests, but it removes the sender from everything the relay stores or hands out, and it moves the receiving connector onto the right trust path (MLS). It is the low-risk part and is implemented (§6).

### 4.3 Option C: sealed sender plus round table

The round table needs the sender: "is it your turn?" is a question about identity. Options:

1. **Round table rooms are not sealed** (the mode is a deliberate metadata trade, as DESIGN.md §12 already said about turn signals). Free rooms can be sealed (option A); round table rooms use the bearer. This is honest and simple: the room's mode says what the relay learns.
2. **Per-seat turn tokens:** when the floor moves to seat `m3`, the relay issues one single-use token to `m3` ("you may send now"); the holder spends it anonymously. The relay learns that *the holder* sent, which it knew anyway (it moved the floor there). Passes and holds are the same. Interrupts need a per-member budget token (one per thread). This keeps enforcement and hides nothing extra, so it only matters together with option A for the free-mode case. Not worth building until A exists.

### 4.4 What stays visible under every option

Honest list, for the threat model:

- **Room membership** (accounts, bots, seats, join and leave times, invite labels) and **who is online**: `e2e_fetch` long-polls are authenticated per bot; the relay sees who is waiting, when, and from which IP.
- **Timing and sizes** of every message, commit and blob; the message count per room; **epochs and who committed** (commits add or remove seats, so the relay needs the committer and the roster delta; sealing commits would mean the relay cannot flip seats or route Welcomes).
- **Doorbell destinations** (ntfy topic hash, webhook host) and when they are rung.
- **IP addresses**, at least at connection time; TLS-level correlation of a token-only send with a bot's other requests from the same address.
- **In 2-member rooms**, elimination: whatever the envelope hides, the other party sent it.
- **Round table state** (holder, order, passes, holds) in round table rooms.
- **Blob uploaders** (the upload is authenticated; sealing uploads is option A again).

What the relay never learns, under any option: message text, titles, file names and contents, file keys, the MLS tree secrets, safety numbers, invite fragments.

## 5. Recommendation

Do option B now (done), keep the bearer on sends, and put option A on the list for after the invite `k=` proof and persistent MLS state, with the honest caveat that it mostly helps groups of three or more against a relay that does not keep connection logs. Treat round table rooms as unsealed by design and say so in the mode's description if A ever lands. Do not build C.2.

## 6. Implemented on this branch (item 4, low-risk part)

- `e2e_fetch` no longer returns `from` on **application** items, and the room actor no longer records a sender on them (`E2eItem.from` is `None` for ciphertext; commits and Welcomes keep their sender, which the relay needs for ordering and the connector uses to verify the inviter's fingerprint).
- The fetch result's `members` list now carries each seat's `agent_id` (metadata the relay already exposes in `get_status`), so the connector maps the **MLS-authenticated** credential identity of a decrypted message to a seat id itself. `sender.member` in a `wait_for_message` result therefore comes from MLS plus the roster, never from a relay claim about the sender.
- The relay still learns the sender of every send at the HTTP layer (bearer, IP, timing) and still uses it for rate limits and the round table. Nothing in this item changes what an operator who logs requests could learn; it changes what the relay stores, hands out, and what the receiving side trusts.
