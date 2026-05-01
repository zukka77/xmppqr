# x3dhpq Design Update — Account Identity, Multi-Device, Group Trust

| Field | Value |
|---|---|
| Status | Draft proposal — under review |
| Replaces | docs/x3dhpq-xep-draft.md §7 (Identity, Devices, and Bundles) |
| Last Updated | 2026-05-01 |
| License | AGPLv3 |

## Motivation: the OMEMO multi-device pain

XEP-0384 OMEMO models trust **per-device**. The natural consequence:

- Alice has 3 devices, Bob has 2 devices, group chat has 5 other members, each with 2-3 devices.
- Per-device verification: Alice must trust 14+ device identities just to talk in this group.
- New device for any participant → **everyone re-verifies**.
- In practice, real users tap "trust" on every prompt → safety degrades to TOFU-by-resignation.

We replace this with **account-level identity + transitive device trust**, so that:

1. A user verifies another user **once**, by AIK fingerprint.
2. A user enrols their own new device by typing a short code on an existing device.
3. Group members observe new devices via PEP and auto-trust them iff they carry a valid signature from an AIK already pinned.
4. Removing a device is a single signed devicelist publish.

## Key hierarchy

```
                   AIK  (Account Identity Key)
                    │   hybrid: Ed25519 + ML-DSA-65 (when wolfSSL/dilithium ready)
                    │
   ┌──────────┬────┴─────┬──────────┐
  DIK1       DIK2       DIK3       DIK4   (Device Identity Keys, hybrid)
   │          │          │          │      each signed by AIK → Device Certificate
   │          │          │          │
 pre-keys   pre-keys   pre-keys   pre-keys (X25519 + ML-KEM-768, as today)
 ratchet    ratchet    ratchet    ratchet
```

- **AIK** is the user's stable identity. *One per account*. Public AIK is what other users pin via fingerprint.
- **DIK** is per-device, generated locally on first run, never leaves the device.
- **Device Certificate (DC)** binds a DIK to the AIK: `Sign_AIK(DIK_pub_ed25519 ‖ DIK_pub_mldsa ‖ device_id ‖ created_at ‖ flags)`. Carried in the bundle.
- **Pre-keys / ratchet** unchanged from the existing XEP draft (X25519 + ML-KEM-768 + Triple Ratchet).

The handshake (`x3dh.go`) doesn't change, but **the receiver now verifies the device's DC against the sender's known AIK** before accepting the session.

### Where AIK_priv lives

Per-device control over AIK_priv determines who can authorize new devices and revoke existing ones.

Default model: **one primary device**.
- AIK_priv is generated on the user's first device (the primary).
- The primary device can authorize new devices and sign devicelist updates.
- Other devices hold only their DIK_priv + a copy of the public AIK + their own DC.
- Lost primary without backup → account unrecoverable in the cryptographic sense (must create a new account).

Optional model: **multi-primary**.
- During pairing, the existing primary may opt to share AIK_priv to the new device.
- The new device becomes co-primary: can authorize further devices.
- Trade-off: convenience vs blast radius. A single compromised primary leaks AIK_priv.
- Mitigation: at-rest encryption with OS keystore (SecureEnclave / TPM / Android Keystore) + audit chain (below).

Recovery model: **encrypted backup blob** (optional, recommended).
- AIK_priv encrypted under a user-chosen passphrase via Argon2id-derived KEK + AES-256-GCM.
- Stored on server as a PEP item (private node, owner-only access) OR exported as a paper key for offline storage.
- Recovers AIK_priv on a fresh device when the user remembers the passphrase.

## Pairing protocol — typed code via PAKE

User experience:
1. On the existing primary, the user picks "Add a device". Display: a 10-digit code with checksum: `123-456-789-X`. TTL: 60 seconds.
2. On the new device, after sign-in to the same JID, the user picks "Pair with existing device" and types the code.
3. Both devices show "Verifying…" and within ~1s show "Paired ✓".

Wire flow:

```
Existing primary (E)                    New device (N)
─────────────────────                  ──────────────────
                                        user signs in to JID
                                        N publishes a temporary
                                        bundle without DC
                                        (marked unsigned)
display code C, t←now+60s

(both devices on same JID, full-JID-to-full-JID via the server)

E: <pair code-hash='H(C)' …/>      ──→  N
                                  ←──   N: <pair-resp pake_msg1=… />
E: <pair-final pake_msg2=… />     ──→  N

   ── PAKE-derived session key K ──

E: encK( DC_for_N, devicelist_v_new,
        [optional AIK_priv blob],
        recent state snapshot ) ──→ N
                                  ←──   N: encK( ack )

E publishes signed devicelist v_new to PEP
N publishes its bundle (now containing DC) to PEP
+notify cascades to contacts & group members
```

### PAKE choice

**CPace** — Curve25519-based PAKE, draft-irtf-cfrg-cpace. Reasons:
- 2-message variant, ~1 RTT per side.
- Integrates with our existing `wolfcrypt.GenerateX25519` + `wolfcrypt.X25519SharedSecret` primitives.
- Resists offline dictionary attacks and online enumeration as long as the server (or any in-path observer) cannot replay both halves.
- 60s TTL + the server's stanza rate limiting bound online attempts to ≤ a few per second per JID.

Code construction:
- 9 random digits + 1 Luhn-mod-10 checksum. ~30 bits effective entropy.
- ~30 bits is fine because:
  - PAKE binds the code to the session — wrong code = unrecoverable handshake failure (no partial-information leak).
  - 60s TTL × per-second rate limiter ≈ ≤ 60 attempts; expected break time of 30-bit PAKE-protected secret is impractical for online attacks.
  - A user can repeat with a fresh code on typo.
- Code displayed as `123-456-789-X` (3-3-3-1 grouping; the `X` is the checksum). UX hides the checksum until "Verify code" tap to reduce visual noise.

### What flows over the PAKE channel

After PAKE establishes session key K (256 bits), one round of authenticated-encryption messages:

E → N (encrypted under K):
- Device certificate `DC_for_N` (E signs N's DIK_pub with AIK_priv).
- Updated devicelist `DL_v_new`, signed by AIK.
- Optional `AIK_priv_blob` if the user chose to make N a co-primary.
- Recent message state snapshot — OPTIONAL onboarding aid: roster, MAM cursors, last-seen-message ids per contact, group memberships. Lets the new device "catch up" without re-fetching everything.

N → E (encrypted under K):
- Acknowledgement of receipt.
- N's first published bundle hash so E can sanity-check it landed in PEP.

### Failure paths

- Wrong code typed → PAKE fails → both UIs show "Invalid code". E doesn't increment any counter on the user's account; the limit is on stanza rate per JID resource pair.
- Code TTL elapses → E discards the pairing context, displays "Code expired".
- N can't reach the server during the pairing window → user retries.
- E's pairing context is per-attempt — never log the code. The server sees only opaque PAKE messages.

## Devicelist format

PEP node `urn:xmppqr:x3dhpq:devicelist:0`, single item id="current".

Logical contents:
```
{
  version: u64                 // monotonic; receivers reject lower
  issued_at: i64               // unix seconds
  devices: [
    { device_id: u32,
      dc: bytes,               // device certificate
      added_at: i64,
      flags: u8 },             // bit 0 = primary
    ...
  ]
  signature: bytes             // AIK_sign(canonical(version‖issued_at‖sorted devices))
}
```

Receivers MUST:
- Verify `signature` against the AIK they have pinned for this user.
- Reject if `version ≤ last_seen_version` (rollback protection).
- Drop any per-device session not present in the new devicelist.
- Establish handshakes with newly listed devices on next outbound message (lazy).

## Audit chain

To detect silent rogue device additions (e.g., AIK_priv compromise):

PEP node `urn:xmppqr:x3dhpq:audit:0`, append-only.

Each entry:
```
{
  seq: u64
  prev_hash: bytes32           // SHA-256 of canonical previous entry; zero if first
  action: enum {ADD, REMOVE, ROTATE_AIK, BACKUP_RECOVERY}
  payload: bytes               // device_id, AIK_pub, etc., depending on action
  timestamp: i64
  signature: bytes             // signed by AIK
}
```

Receivers SHOULD periodically tail the audit chain and surface UX:
> "Alice added a new device 'Pixel-9' on May 1, 14:32 UTC. Was that you?"

A compromised device that adds itself can't suppress the audit entry without burning the AIK signature. Detection is post-hoc but reliable.

## Group chat — AIK-based membership

A MUC room's logical encrypted membership is a **set of AIK public keys**, not full JIDs and not per-device.

Room metadata (e.g., room config form extension):
- `members[i].aik_pub` — list of pinned AIKs that may participate.
- `members[i].jid` — the bare JID associated with that AIK (cosmetic, not authoritative).
- `members[i].role` — visitor / participant / moderator / owner.

Encrypted message flow:
1. Sender (one of Alice's devices) generates payload key MK.
2. Sender encrypts MK to each recipient device's per-pair session — exactly as in 1:1 chat — using the **device certificates from each member's currently published devicelist**.
3. Sender includes the resulting `<keys>` map covering all currently-known recipient devices across all members of the room.
4. AEAD payload encrypted under MK.
5. Stanza routed via MUC.

Trust evaluation per recipient device:
- Look up the recipient's AIK in our pinned set for this room.
- Fetch their devicelist from PEP (cached, refreshed on +notify).
- Verify the DC for `device_id` against the pinned AIK.
- If valid → encrypt to that device. NO USER PROMPT.

When Alice adds a new device:
- Alice's primary signs new DC.
- Devicelist v+1 published.
- All group members observe via +notify.
- Their clients verify the DC against Alice's pinned AIK → add the device-id to their encrypt-set.
- Next outbound message includes Alice's new device automatically.
- **No user interaction at any group member.**

When Bob is removed from a group:
- Owner publishes membership change.
- Other members rotate group state (new sender-chain epoch, see "Group ratchet" below).
- Stop encrypting to Bob's AIK going forward.

When Bob loses a device:
- Bob's primary signs new devicelist excluding the lost device.
- Group members observe; drop that device's session.
- Bob's other devices unaffected.

## Group ratchet — sketch (not finalized)

Final design deferred to a separate proposal. Working sketch:

- **Sender keys per device** (Megolm/Signal-group-keys hybrid).
- Each room participant device maintains a sending chain (`epoch`, `chain_index`, `chain_key`).
- Initial distribution: when a device first sends in a room, it distributes its sender chain key to every recipient device via pairwise x3dhpq sessions (one stanza or piggyback on first outbound message).
- Per-message: derive MK from chain, encrypt body. Header: `epoch || chain_index || sender_device_id`.
- **Epoch rotation triggers**: member removed; member's device removed; periodic interval (default 24h or 1000 messages, whichever first); after a KEM checkpoint window expires.
- **Forward secrecy after removal**: epoch rotation generates a new sender chain key NOT distributed to the removed party. Past messages remain readable (if device kept history); future messages are unreadable to the removed party.
- **PQ checkpoints in groups**: less frequent than 1:1 (groups are fan-out heavy). Default once per epoch rotation.

Non-goals for v1 group chat:
- Anonymous membership (every member knows every other member's AIK).
- Anonymous senders (sender always identified by AIK + device_id in the header).
- Strong post-compromise security against a member who joins late and then is removed (we trade some PCS for fan-out efficiency).

## Cross-user verification UX

Per-user, not per-device:

- One **safety number** per user pair: `BLAKE2b-160(sort(AIK_pub_alice, AIK_pub_bob))` displayed as 30 hex chars in `XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX` format.
- QR code: encodes `(AIK_pub, jid, checksum)` of the local user; counterparty scans → both clients confirm match → both pin AIK.
- Once pinned, ALL of that user's signed devices auto-trust forever (until AIK rotation).
- A device with a DC NOT signed by the pinned AIK is rejected silently — no "trust this device?" prompt.

## AIK rotation

Optional feature for users who suspect AIK_priv compromise.

Process:
1. Existing AIK signs a "rotation pointer": `Sign_oldAIK(new_AIK_pub ‖ rotation_seq ‖ timestamp)`.
2. New AIK_priv generated; new AIK signs new devicelist + new DCs for all current devices.
3. Old AIK is marked superseded but its rotation pointer remains in the audit chain forever.

Verification by other users:
- Detect the rotation entry via audit-chain tail.
- **Surface for re-verification**: `"Alice's identity has rotated. This may be normal (device replaced) or suspicious (key compromise). Re-verify out of band."`.
- Until re-verified out of band, the user's clients MAY continue accepting messages (with a UX warning) OR MAY refuse (configurable). Default: warn but accept; aggressive policy refuses.

The rotation pointer is itself a signal that an attacker with AIK_priv access can forge — so re-verification by AIK fingerprint comparison is required before fully retrusting.

## Server side (x3dhpq transport rules — no protocol-level changes)

The server doesn't need new logic for any of the above. The PEP infrastructure already:
- Hosts the user's devicelist (existing node).
- Hosts the audit chain (new node: `urn:xmppqr:x3dhpq:audit:0`, +notify enabled).
- Fans out devicelist + audit changes via XEP-0163 +notify (Wave 8b).
- Enforces per-item byte caps (the audit chain is append-only and can grow; cap at 1 MiB initially, rotation/pruning policy TBD).
- Treats pairing stanzas opaquely — just route between full JIDs of the same bare JID.

Server reservations:
- Reserve a new namespace `urn:xmppqr:x3dhpq:pair:0` for the typed-code pairing PAKE messages. Treat as opaque pass-through, like existing envelope handling.
- Optionally rate-limit pairing stanzas per (resource_from, resource_to) to slow online code-guessing.

## What is NEW vs the existing XEP draft

| Area | Existing draft | This proposal |
|---|---|---|
| Identity | Per-device hybrid (Ed25519 + ML-DSA) | Account AIK + per-device DIK signed by AIK |
| Verification | Per-device fingerprint | Single AIK fingerprint per user |
| New device | Out-of-band fingerprint share or trust-on-first-use | Typed PAKE code from existing device |
| Group trust | TBD (deferred) | AIK-based membership, devices auto-trust under AIK |
| Group ratchet | Not specified | Sender-keys per device with epoch rotation on membership change (sketched, final TBD) |
| Audit | Not specified | Append-only PEP node `:audit:0` with hash chain |
| Recovery | Not specified | Encrypted AIK_priv backup with Argon2-derived KEK; paper key option |
| Bundle wire format | DIK_pub directly | DC (DIK_pub + AIK signature) |
| Devicelist | Plain list of device-ids | Versioned, signed-by-AIK, rollback-resistant |

## Open questions for review

1. **Default primary count: 1 or auto-promote?** The minimal-attack-surface answer is 1; the user-friendly answer is to auto-promote any newly paired device. We default to 1 (user opts in to multi-primary at pair time).
2. **Audit chain location**: server-hosted PEP (transparent to contacts) vs purely local on each device (private). I recommend server-hosted: it's already encrypted with the user's own metadata visible only to themselves and (optionally) explicit audit-chain subscribers.
3. **AIK rotation re-verification policy**: warn-and-accept (lenient) vs hard-refuse (strict). Default: warn-and-accept; expose strict mode in client config.
4. **PAKE algorithm**: CPace (proposed) vs SPAKE2 (simpler). CPace is faster and standardised in IETF; SPAKE2 is more widely implemented. I lean CPace.
5. **Code format**: 9+1 digits (proposed) vs 6+1 (less to type, less entropy) vs 12+1 (more secure, painful UX). Decide based on PAKE entropy budget; 9+1 = ~30 bits is the sweet spot for 60s TTL + rate-limited online attempts.
6. **Group membership semantics**: do we leak AIK_pub of all members to all members? (Yes, in this proposal — like Signal groups.) Anonymous-sender groups are out of scope for v1.
7. **Lost primary recovery**: do we ship the encrypted-backup feature in v1 or punt it to v1.1? Recommendation: v1, since "lost primary = unrecoverable" is a serious UX cliff.
8. **Group ratchet final design**: sender-keys vs MLS-style tree? The sketch above is sender-keys. MLS is more elegant for very large groups but heavier. v1 recommendation: sender-keys; revisit at scale.

## Out of scope (this proposal)

- Anonymous groups (membership privacy).
- Cross-server account portability (same AIK across multiple JIDs).
- Constant-time crypto audits (assumed to be addressed by wolfCrypt).
- Final XML schema (deferred to Stable-track XEP advancement).
- Concrete group ratchet wire format (sketched only).
