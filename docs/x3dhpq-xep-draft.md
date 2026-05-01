<!--
  SPDX-License-Identifier: AGPL-3.0-or-later
  xmppqr project — project-internal draft, not yet submitted to XSF
-->

| Field          | Value                                                                        |
|----------------|------------------------------------------------------------------------------|
| WIP Number     | XEP-XQR                                                                      |
| Status         | Experimental (project-internal draft)                                        |
| Type           | Standards Track                                                              |
| Version        | 0.2.0                                                                        |
| Last Updated   | 2026-04-30                                                                   |
| Author         | xmppqr project                                                               |
| License        | AGPLv3                                                                       |
| Namespace      | urn:xmppqr:x3dhpq:0                                                         |
| Dependencies   | XEP-0163 (PEP), XEP-0060 (PubSub), RFC 6120/6121                            |

---

# XEP-XQR: x3dhpq — Hybrid Post-Quantum E2EE for XMPP with Multi-Device Cross-Signing

## 1. Abstract

This document specifies x3dhpq-over-XMPP, a protocol for end-to-end encrypted (E2EE) messaging on XMPP networks. The protocol provides post-quantum confidentiality through a hybrid construction — every pairwise session combines classical X25519 Diffie-Hellman with ML-KEM-768 (FIPS 203) key encapsulation to derive a shared root key, which is subsequently protected by a Triple Ratchet (Signal Double Ratchet augmented with periodic ML-KEM-768 checkpoints). Account-level identity is anchored in an **Account Identity Key (AIK)**, a long-term Ed25519 key. Each device holds a **Device Identity Key (DIK)** bound to the AIK by a **Device Certificate (DC)**, enabling users to verify each other once by AIK fingerprint while new devices enrol automatically via a CPace PAKE pairing protocol. An append-only **audit chain** records all device additions, removals, AIK rotations, and recovery events. Group sessions use per-device sender chains (Megolm-style) with epoch rotation on membership change. AIK backup and recovery use scrypt-derived AES-256-GCM sealed blobs optionally encoded as human-readable paper keys. The XMPP server is explicitly transport-only: it never holds keys, never decrypts content, and never inspects message envelopes.

---

## 2. Introduction

### 2.1. Motivation

Store-and-forward messaging networks such as XMPP are uniquely vulnerable to harvest-now-decrypt-later (HNDL) attacks. A nation-state adversary recording encrypted XMPP traffic today can attempt decryption once a sufficiently large cryptographically-relevant quantum computer (CRQC) becomes available. Because XMPP servers routinely archive messages (XEP-0313), and because forward-secrecy ratchets rotate keys only gradually, the exposure window can span years.

XEP-0384 OMEMO, the current XMPP E2EE standard, is based on Signal's Double Ratchet and X3DH. Both X25519 and the underlying symmetric construction are secure against classical adversaries. However, the X3DH key agreement step and the Diffie-Hellman ratchet are broken by Shor's algorithm on a CRQC. OMEMO therefore provides no post-quantum security in its current form.

A second, independent problem compounds the first: OMEMO models trust **per-device**. In a group chat with N participants each owning M devices, every member must individually verify N×M device identities. In practice, real users tap "trust" on every prompt — security degrades to TOFU-by-resignation. Adding a device for any participant requires every other participant to re-verify.

This specification addresses both problems. It defines:

1. A Triple Ratchet construction (X25519 Double Ratchet + periodic ML-KEM-768 checkpoints) that resists HNDL attacks.
2. An account-level identity hierarchy (AIK → DIK → DC) that reduces multi-device trust to a single per-user verification.
3. A CPace PAKE pairing protocol for frictionless device enrolment.
4. An append-only audit chain for post-hoc detection of unauthorized device additions.
5. Sender-key group sessions with epoch rotation on membership change.
6. scrypt-based AIK backup and paper-key recovery.

### 2.2. Relation to OMEMO (XEP-0384) and Signal's SPQR

x3dhpq-over-XMPP shares OMEMO's broad architecture: devices publish cryptographic bundles via PEP (XEP-0163 / XEP-0060), senders encrypt per-device keys, and the server routes opaque ciphertext. The key differences are:

1. **PQ hybrid key agreement**: X3DH is replaced by PQXDH, which incorporates an ML-KEM-768 encapsulation step. The root key is derived from both X25519 and KEM shared secrets (HKDF-SHA-512 throughout).
2. **Triple Ratchet**: Signal's Double Ratchet is augmented with a Sparse PQ Ratchet (SPQR). Every K messages or after T seconds of inactivity, a fresh ML-KEM-768 encapsulation checkpoint injects entropy into the root key derivation.
3. **Account identity**: Long-term identity is represented as an **AIK** — an Ed25519 keypair in the current implementation, with ML-DSA-65 fields reserved for future use (see §5). Bundles include a **Device Certificate** signed by the AIK instead of a bare DIK public key.
4. **Group sender keys**: Group sessions use per-device sender chains distributed pairwise, similar to Signal's group key design and Megolm.
5. **Server role**: OMEMO servers are already transport-only in theory; this specification makes that property explicit and defines server-enforced policies.

The ratchet semantics and KEM checkpoint logic are adapted from Signal's SparsePostQuantumRatchet reference implementation at `github.com/signalapp/SparsePostQuantumRatchet`. This document re-binds the wire format to XMPP stanzas.

### 2.3. Design Goals

- **PQ confidentiality at session establishment** (HNDL resistance): an adversary recording traffic today cannot decrypt it with a future CRQC.
- **Per-user, not per-device trust**: verify once by AIK fingerprint; all devices under that AIK are transitively trusted.
- **Frictionless new-device enrolment**: a 10-digit typed code on an existing device suffices.
- **Deniable recovery path**: encrypted AIK backup allows account recovery on a fresh device with no involvement of other users.
- **Audit transparency**: an append-only PEP chain lets users detect unauthorized device additions after the fact.
- **Server opacity**: the server learns nothing about message content, session keys, or ratchet state.

---

## 3. Requirements

This document uses RFC 2119 key words.

- **REQ-1**: Message confidentiality MUST be maintained against both classical and quantum adversaries at the point of initial key agreement (HNDL resistance).
- **REQ-2**: The protocol MUST provide forward secrecy: compromise of current keying material MUST NOT enable decryption of past messages.
- **REQ-3**: The protocol MUST provide post-compromise security: after a device compromise, security MUST be automatically restored within at most K messages or T seconds, without user action.
- **REQ-4**: The server MUST NOT be able to decrypt any message or derive any session key.
- **REQ-5**: Clients that do not support x3dhpq-over-XMPP MUST be able to coexist on the same server without disruption (unless the server is operating in x3dhpq-only mode, Section 15.6).
- **REQ-6**: The protocol MUST be implementable using only NIST-standardized post-quantum primitives (FIPS 203; FIPS 204 reserved for future use).
- **REQ-7**: Protocol overhead (bundle size, per-message overhead) MUST be bounded and documented.
- **REQ-8**: A user MUST be able to verify another user's identity with a single out-of-band comparison (AIK fingerprint or QR code). All of that user's devices MUST be transitively trusted after that single verification.
- **REQ-9**: Adding a new device MUST NOT require any action from contacts; the new device MUST be automatically included in future messages to those contacts.
- **REQ-10**: The protocol MUST provide a recovery path in case the primary device holding AIK_priv is permanently lost.

---

## 4. Glossary

| Term | Definition |
|------|------------|
| **AEAD** | Authenticated Encryption with Associated Data |
| **AIK** | Account Identity Key — long-term Ed25519 key (ML-DSA-65 fields reserved), one per account |
| **AIK fingerprint** | BLAKE2b-160 of the canonical-encoded AIK public key, displayed as 30 hex chars in 6 groups of 5 |
| **Audit chain** | Append-only PEP node recording AIK-signed events (add/remove device, rotate AIK, recover) |
| **ChainKey (CK)** | Symmetric key used to advance the sending or receiving chain |
| **CPace** | Composable Password-Authenticated Key Exchange; IETF draft-irtf-cfrg-cpace |
| **CRQC** | Cryptographically-Relevant Quantum Computer |
| **DC (Device Certificate)** | AIK-signed binding of a DIK to an account, with device ID, creation time, and flags |
| **DHR** | Diffie-Hellman Ratchet key pair (per-ratchet-step, classical X25519) |
| **DIK** | Device Identity Key — per-device hybrid key (Ed25519 + X25519 + ML-DSA-65 reserved), never leaves the device |
| **Double Ratchet** | Signal's Double Ratchet Algorithm combining a KDF chain with a DH ratchet |
| **E2EE** | End-to-End Encryption |
| **Epoch** | Contiguous sender-chain segment in a group session; rotated on membership change |
| **HNDL** | Harvest-Now-Decrypt-Later — recording ciphertext for later quantum decryption |
| **HKDF-SHA-512** | HKDF (RFC 5869) instantiated over SHA-512 (used throughout this spec) |
| **KDF** | Key Derivation Function |
| **KEM** | Key Encapsulation Mechanism |
| **KEM checkpoint** | A Triple Ratchet step that injects a fresh ML-KEM-768 shared secret into the root key |
| **MessageKey (MK)** | Ephemeral AEAD key derived from ChainKey for a single message |
| **ML-DSA-65** | Module-Lattice Digital Signature Algorithm, FIPS 204, NIST security level 3 — reserved, not yet active |
| **ML-KEM-768** | Module-Lattice Key Encapsulation Mechanism, FIPS 203, NIST security level 3 |
| **OMEMO** | XEP-0384, the existing XMPP E2EE protocol based on Signal's Double Ratchet |
| **OPK** | One-Time Pre-Key (classical X25519) |
| **Paper key** | Human-readable encoding of a sealed AIK backup blob (base32, grouped, with header) |
| **PEP** | Personal Eventing Protocol (XEP-0163 / XEP-0060) |
| **PQ** | Post-Quantum |
| **Primary device** | A device that holds AIK_priv and can sign new DCs and devicelists |
| **RootKey (RK)** | Top-level key from which ChainKeys are derived via KDF ratchet |
| **Sender chain** | Megolm-style per-device symmetric chain used in group sessions |
| **SPK** | Signed Pre-Key (classical X25519, signed with DIK) |
| **SPQR** | Sparse Post-Quantum Ratchet — Signal's Triple Ratchet construction |
| **Triple Ratchet** | Double Ratchet + Sparse PQ Ratchet |
| **X3DH** | Extended Triple Diffie-Hellman (classical initial key agreement) |
| **PQXDH** | Post-Quantum Extended Triple Diffie-Hellman (Signal's PQ key agreement spec) |

---

## 5. Cryptographic Primitives

All cryptographic operations MUST use the following primitives. Implementations MUST NOT substitute weaker alternatives without explicit version negotiation.

### 5.1. Asymmetric Primitives

| Primitive | Role | Reference |
|-----------|------|-----------|
| X25519 | Classical DH ratchet, SPK, OPK, CPace | RFC 7748 |
| Ed25519 | AIK and DIK signature (current active component) | RFC 8032 |
| ML-KEM-768 | KEM pre-keys, PQXDH handshake, Triple Ratchet checkpoints | FIPS 203 |
| ML-DSA-65 | PQ signature component for AIK and DIK — **reserved, nil in v1** | FIPS 204 |

**Note on ML-DSA-65**: The wire formats for AIK, DIK, and DC include ML-DSA-65 fields as length-prefixed byte strings. In the current implementation these fields are always nil/zero-length. The wolfSSL build configuration required for ML-DSA-65 support (Dilithium/wolfSSL build flags) has not been finalized. When a future implementation populates these fields, all verification routines MUST require both Ed25519 and ML-DSA-65 signatures to be valid. Parsers MUST tolerate nil ML-DSA-65 fields without error.

### 5.2. Symmetric Primitives

| Primitive | Role | Reference |
|-----------|------|-----------|
| HKDF-SHA-512 | All KDF operations (root key, chain key, message key, KEM mixing) | RFC 5869 |
| AES-256-GCM | AEAD encryption of message payloads, pairing channel, recovery blob | NIST SP 800-38D |
| HMAC-SHA-256 | Chain key advancement within the Double Ratchet | RFC 2104 |
| BLAKE2b-160 | AIK fingerprint computation | RFC 7693 |
| scrypt (N=131072, r=8, p=1) | Key derivation from recovery passphrase | RFC 7914 |
| SHA-256 | Audit chain hash linking | FIPS 180-4 |

**KDF implementation note**: `hkdf64`, `hkdf32`, and `hkdf44` throughout the codebase use `wolfcrypt.HKDFExtract` and `wolfcrypt.HKDFExpand` which are internally SHA-512-based. When a zero-length salt is provided, the implementation substitutes a 64-byte zero salt. This matches the HKDF specification behavior.

**scrypt vs Argon2id**: The recovery KDF uses scrypt (RFC 7914) rather than Argon2id. Argon2id was considered but rejected because wolfCrypt does not ship it; introducing `golang.org/x/crypto/argon2` would be the sole non-wolfCrypt crypto dependency. RFC 7914 scrypt with N=131072, r=8, p=1 provides equivalent memory-hardness for the intended use case.

### 5.3. KDF Constructions

**Root key derivation (DH ratchet steps):**

```
RK', CK' = HKDF-SHA-512(
    salt  = RK,
    ikm   = X25519(dh_priv, dh_pub),
    info  = "X3DHPQ-RootKey-v0"
) -> split 32 || 32 bytes
```

**Initial hybrid root key (PQXDH handshake):**

```
RK = HKDF-SHA-512(
    salt  = <zero 64 bytes>,
    ikm   = dh1 || dh2 || dh3 [|| dh4] || kem_ss,
    info  = "X3DHPQ-X3DH-PQ-v0"
) -> 64 bytes; first 32 = RK, second 32 = initial CK
```

where `dh1..dh4` are X25519 shared secrets and `kem_ss` is the ML-KEM-768 shared secret. The KEM shared secret MUST be appended last in the IKM concatenation.

**KEM checkpoint (Triple Ratchet):**

The KEM checkpoint serves two distinct purposes that operate on different state:

1. **Immediate chain healing**: it re-derives both directions' symmetric chain keys (`ChainSendKey`, `ChainRecvKey`) using the ML-KEM-768 shared secret, so the next message's MK is unrecoverable from the pre-checkpoint chain key alone.
2. **Deferred root-key healing**: it accumulates the KEM entropy into a 32-byte `KEMHistory` digest that both parties carry forward. At the next DH ratchet step, `KEMHistory` is folded into the IKM of `KDF_RK`, so the post-DH-ratchet `RK` is unrecoverable without every observed `kem_ss`.

This split is necessary because the Double Ratchet's `RK` is intentionally desynchronized between sender and receiver in any asymmetric flow: when the receiver processes a DH-ratchet message, they perform two `KDF_RK` updates (one for the receive chain, one for a fresh send chain), while the sender performs only one. Mixing `kem_ss` directly into `RK` would therefore fail to converge between sides. `KEMHistory` is an explicit, deterministic, bidirectionally-synchronized accumulator that captures the same PQ entropy without disturbing the Double Ratchet's `RK` invariant.

```
kem_ss = ML-KEM-768.Decaps(kem_ct, kem_priv)   // or Encaps output on sender

transcript_hash = SHA-512(
    "X3DHPQ-Checkpoint-Transcript-v1\0" ||
    uint32-be(epoch)                    ||   // sender's SendCount at checkpoint
    dh_pub_sender                       ||   // sender's DH pub from the message header
    kem_ct                                   // the ML-KEM-768 ciphertext in the header
)

senderCK = sender's ChainSendKey  (≡ receiver's ChainRecvKey at checkpoint time)

prk     = HKDF-Extract(salt = senderCK, ikm = kem_ss || transcript_hash)
CKs_new = HKDF-Expand (prk, info = "X3DHPQ-ChainSend-v1", L = 32)
CKr_new = HKDF-Expand (prk, info = "X3DHPQ-ChainRecv-v1", L = 32)

KEMHistory_new = SHA-512(
    "X3DHPQ-KEMHistory-v1\0" ||
    KEMHistory_prev          ||
    kem_ss                   ||
    transcript_hash
)[:32]

// State update (sender)
ChainSendKey ← CKs_new
ChainRecvKey ← CKr_new
KEMHistory   ← KEMHistory_new
RK           unchanged

// State update (receiver)
ChainRecvKey ← CKs_new       // receiver's recv chain == sender's send chain
ChainSendKey ← CKr_new       // and conversely
KEMHistory   ← KEMHistory_new
RK           unchanged
```

The DH ratchet step then becomes:

```
dh_out = X25519(my_dh_priv, peer_dh_pub)
RK_new, CK_new = HKDF(salt = RK,
                      ikm  = dh_out || KEMHistory,
                      info = "X3DHPQ-RootKey-v1",
                      L    = 64)
RK ← RK_new[:32]
chain_key ← RK_new[32:]
```

Both parties update `KEMHistory` identically at every checkpoint. Both parties also feed identical inputs into `KDF_RK` at every DH ratchet step. So the `RK` resulting from any DH ratchet step *after* a KEM checkpoint depends on every `kem_ss` observed since the session began — whether or not the attacker observed `RK` at any earlier point.

The `transcript_hash` binds the checkpoint to the specific message: an attacker who replaces `kem_ct` or `dh_pub_sender` causes the receiver's `prk` to differ, the receiver's chain keys to diverge, and the next message's AEAD to fail. We deliberately omit the receiver's DH pub from `transcript_hash` because in an asymmetric flow the sender's view of "receiver's current DH" lags the receiver's own current DH (receiver regenerates on each DH ratchet step) and including it would prevent convergence.

**Post-compromise security claim (Triple Ratchet, 1:1):**

After a successful KEM checkpoint at message *N* where the attacker did not observe the corresponding `kem_ss`:

- Messages *N* and later in both directions cannot be decrypted using only the pre-checkpoint `ChainSendKey` and `ChainRecvKey`.
- After the next DH ratchet step (in either direction), the resulting `RK` cannot be derived from the pre-checkpoint `RK` and observed protocol messages.
- All chain keys subsequently derived from the post-DH-ratchet `RK` inherit this property.

The recovery is bounded: an attacker who holds `RK`, `ChainSendKey`, `ChainRecvKey`, *and* `KEMHistory` at any point can derive all subsequent state until the next checkpoint. Healing requires (a) a KEM checkpoint event the attacker missed *and* (b) a DH ratchet step subsequent to that checkpoint. Group sender-key sessions (§13) do not provide this property; their security claims are described separately.

**Chain key advancement:**

```
MK      = HMAC-SHA-256(CK, 0x01)
CK_next = HMAC-SHA-256(CK, 0x02)
```

**Message key expansion (AES-256-GCM key + nonce):**

```
AES_key || nonce = HKDF-SHA-512(
    salt  = <zero 64 bytes>,
    ikm   = MK,
    info  = "X3DHPQ-MessageKey-v0",
    len   = 44   // 32-byte AES-256 key + 12-byte GCM nonce
)
```

### 5.4. AIK Fingerprint

The AIK fingerprint is computed as:

```
fingerprint_bytes = BLAKE2b-160(AIK.Marshal())
fingerprint_display = hex(fingerprint_bytes[:15]) formatted as "XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX"
```

where `AIK.Marshal()` produces the canonical encoding: `uint16(version=1) | uint8(hasMLDSA) | 32 bytes Ed25519_pub | (optional variable-length ML-DSA-65_pub)`. The display truncates 20 bytes (40 hex chars) to 30 hex chars (the first 15 bytes) arranged in 6 groups of 5 characters separated by spaces.

### 5.5. Encoding

All binary cryptographic values appearing in XML MUST be encoded as standard Base64 (RFC 4648 §4, with `=` padding). Whitespace within Base64 strings MUST be ignored by parsers.

---

## 6. Namespaces

| Namespace | Purpose |
|-----------|---------|
| `urn:xmppqr:x3dhpq:0` | Root / disco feature |
| `urn:xmppqr:x3dhpq:bundle:0` | Device bundle PEP node |
| `urn:xmppqr:x3dhpq:devicelist:0` | Versioned signed device list PEP node |
| `urn:xmppqr:x3dhpq:envelope:0` | Pairwise message envelope element |
| `urn:xmppqr:x3dhpq:pair:0` | CPace PAKE pairing messages |
| `urn:xmppqr:x3dhpq:audit:0` | Audit chain PEP node |
| `urn:xmppqr:x3dhpq:recovery:0` | Encrypted AIK backup PEP node |
| `urn:xmppqr:x3dhpq:group:0` | Group session sender-chain announcements |

The namespace `urn:xmppqr:x3dhpq:0` MUST be advertised in the server's service discovery features (XEP-0030) when the server supports this specification. See Section 15.5.

The server additionally advertises `urn:xmppqr:x3dhpq:devicelist:0+notify` and `urn:xmppqr:x3dhpq:audit:0+notify` to signal that those PEP nodes support the +notify subscription semantics (XEP-0163 §6).

---

## 7. Identity Hierarchy

### 7.1. Account Identity Key (AIK)

The AIK is the user's stable, account-scoped long-term identity. There is exactly one AIK per account (under normal operation). The AIK public key is what contacts pin when they verify the user's identity.

Current wire representation (`AccountIdentityPub.Marshal()`):

```
uint16 version (= 1)
uint8  hasMLDSA (= 0 in v1; 1 when ML-DSA-65 is present)
32 bytes  Ed25519 public key
[variable ML-DSA-65 public key, present only if hasMLDSA = 1]
```

The AIK private key (`AccountIdentityKey`) holds:
- `PrivEd25519` (64 bytes): Ed25519 private key (wolfCrypt seed+pub encoding).
- `PubEd25519` (32 bytes): Ed25519 public key.
- `PubMLDSA` (nil in v1): ML-DSA-65 public key, reserved.

All AIK-signing operations in v1 use `wolfcrypt.Ed25519Sign(AIK.PrivEd25519, signedPart)`. When `PubMLDSA` is non-nil, an additional ML-DSA-65 signature MUST be appended, and verification MUST require both signatures to pass.

### 7.2. Device Identity Key (DIK)

Each device generates a DIK locally on first run. The DIK MUST NOT leave the device in plaintext (it may be transferred encrypted over the pairing channel). The DIK contains:

- `PubEd25519` (32 bytes): used for signing within the device.
- `PubX25519` (32 bytes): used as the base key in X3DH / PQXDH.
- `PubMLDSA` (nil in v1): reserved.
- Corresponding private keys, stored encrypted at rest.

### 7.3. Device Certificate (DC)

A DC is produced by the primary device (holding AIK_priv) and binds a DIK to the account. The DC wire format (`DeviceCertificate.Marshal()`) encodes:

```
uint16  version (= 1)
uint32  device_id
uint16  ed25519_pub_len | <DIKPubEd25519>
uint16  x25519_pub_len  | <DIKPubX25519>
uint16  mldsa_pub_len   | <DIKPubMLDSA>    (len=0 in v1)
int64   created_at      (unix seconds)
uint8   flags           (bit 0 = primary)
uint16  sig_len         | <Ed25519 signature by AIK over SignedPart>
uint16  mldsa_sig_len   | <ML-DSA-65 signature> (len=0 in v1)
```

`SignedPart` is the canonical byte sequence:

```
uint16  version
uint32  device_id
uint16  len | <DIKPubEd25519>
uint16  len | <DIKPubX25519>
uint16  len | <DIKPubMLDSA>
int64   created_at
uint8   flags
```

Verification (`dc.Verify(aikPub)`) checks the Ed25519 signature using `aikPub.PubEd25519`. A DC with an invalid signature MUST be rejected; a DC with a nil ML-DSA-65 signature is accepted in v1 (ML-DSA-65 fields are reserved).

### 7.4. AIK Fingerprint and Verification

The AIK fingerprint is a 30-character hex string (see §5.4), displayed as six groups of five: e.g., `A1B2C 3D4E5 F6A7B 8C9D0 E1F2A 3B4C5`.

Users verify each other's identity by comparing AIK fingerprints out-of-band (voice call, QR code scan, in-person). The QR code encodes the tuple `(AIK_pub_canonical_bytes, bare_JID)`. Upon a successful scan, the client stores the AIK fingerprint for that JID. From that point:

- Any DC signed by the pinned AIK is automatically trusted (no user prompt).
- A DC NOT signed by the pinned AIK MUST be rejected silently.
- Any new device the user adds via pairing (Section 10) automatically becomes trusted to all contacts who have already pinned the AIK — no re-verification required.

### 7.5. AIK_priv Storage Models

The location of AIK_priv determines who can authorize new devices and publish signed devicelists.

**Single-primary model (default)**: AIK_priv lives on exactly one device (the device on which it was first generated). Other devices hold only their DIK_priv + public AIK + their own DC.
- Upside: minimal blast radius; AIK_priv compromise requires compromising exactly one device.
- Downside: if the primary is permanently lost without a backup, the account cannot issue new DCs. Users SHOULD maintain a recovery blob (Section 14).

**Multi-primary model (opt-in at pairing time)**: During pairing, the existing primary may opt to transfer AIK_priv to the new device (via the PAKE-encrypted issuance payload, Section 10.4). The `DeviceFlagPrimary` flag in the DC is set. Any primary can issue DCs and sign devicelists.
- Upside: redundancy; account operations do not depend on a single device.
- Downside: a compromised primary leaks AIK_priv to an attacker. Mitigation: at-rest encryption via OS keystore (Secure Enclave / TPM / Android Keystore), combined with audit chain monitoring.

The `SharePrimary` option in `PairingOptions` controls this at pairing time. The decision is per-pairing and recorded in the DC's `flags` field.

---

## 8. Device List

### 8.1. PEP Node and +notify

The device list is published as a PEP item at node `urn:xmppqr:x3dhpq:devicelist:0` with `item id='current'`. The PEP node MUST be configured with `+notify` enabled so that contacts receive real-time updates when the list changes.

Clients MUST subscribe to the devicelist node of their own account and of every contact. A device that appears in the devicelist but whose DC fails verification (Section 8.4) MUST be treated as untrusted.

### 8.2. Versioned Signing and Rollback Resistance

Each devicelist is signed by the AIK and carries a monotonically increasing `version` counter (uint64). Receivers:

1. Verify the AIK signature.
2. Check `version > last_seen_version`. If not (rollback attempt), reject.
3. Verify the DC for each listed device against the AIK (Section 7.3).
4. Drop pairwise session state for device IDs no longer present in the list.
5. Initiate sessions with newly listed devices on the next outbound message (lazy).

The signed input (`DeviceList.SignedPart()`) uses the domain separator `"X3DHPQ-DeviceList-v1\x00"` followed by version, issued_at, and the canonical encoding of all devices sorted by device_id in ascending order. This ensures the canonical form is deterministic regardless of insertion order.

### 8.3. Wire Format

```
uint16  version_marker (= 1)
uint64  version        (monotonic; receivers reject if <= last seen)
int64   issued_at      (unix seconds)
uint16  num_devices
[for each device, sorted by device_id ascending:]
  uint32  device_id
  int64   added_at
  uint8   flags
  uint32  cert_len
  <cert_len bytes: DeviceCertificate.Marshal()>
uint16  sig_len
<sig_len bytes: Ed25519 signature by AIK over SignedPart>
```

### 8.4. Informative XML Example

```xml
<iq type='set' from='alice@example.org/phone' id='pub-dl-1'>
  <pubsub xmlns='http://jabber.org/protocol/pubsub'>
    <publish node='urn:xmppqr:x3dhpq:devicelist:0'>
      <item id='current'>
        <devicelist xmlns='urn:xmppqr:x3dhpq:devicelist:0'
                    version='7'
                    issued-at='1714483200'>
          <device id='31415926' flags='1'> <!-- flags bit 0 = primary -->
            <cert><<base64-device-certificate>></cert>
          </device>
          <device id='27182818' flags='0'>
            <cert><<base64-device-certificate>></cert>
          </device>
        </devicelist>
        <sig><<base64-aik-ed25519-signature>></sig>
      </item>
    </publish>
  </pubsub>
</iq>
```

The exact XML schema is informative; the wire format defined in Section 8.3 is normative. Formal XSD/RNC schemas are deferred to Stable advancement.

### 8.5. Verification Rules

A receiver MUST reject a devicelist if any of the following conditions hold:

- `version_marker != 1`
- The AIK signature does not verify.
- `version <= last_seen_version` (rollback protection).
- Any embedded DC fails verification against the AIK (see §7.3).
- `issued_at` is more than 300 seconds in the future relative to the receiver's clock (clock skew guard).

A receiver SHOULD warn the user if a previously trusted device_id disappears from the list.

---

## 9. Bundles and Pairwise Session Establishment

### 9.1. Bundle Contents

Each device publishes a bundle at PEP node `urn:xmppqr:x3dhpq:bundle:0` with `item id` equal to the device ID (decimal string).

The bundle (`PublicBundle`) contains:

- `DeviceCert`: the device's DC (Section 7.3).
- `IdentityPubX25519`: the DIK's X25519 public key (32 bytes) — used as the IK in X3DH.
- `SPKPub`: the current Signed Pre-Key (X25519, 32 bytes).
- `SPKSig`: Ed25519 signature by the DIK over the SPK public key bytes.
- `KEMPreKeys`: one or more ML-KEM-768 encapsulation public keys (each 1184 bytes), each with an ID.
- `OPKs`: one or more X25519 one-time pre-keys (each 32 bytes), each with an ID.

Clients MUST verify `SPKSig` against `DeviceCert.DIKPubEd25519` before using any key material. A bundle whose signature fails verification MUST be rejected.

#### 9.1.1. Informative XML Example

```xml
<iq type='set' from='alice@example.org/phone' id='pub-bundle-1'>
  <pubsub xmlns='http://jabber.org/protocol/pubsub'>
    <publish node='urn:xmppqr:x3dhpq:bundle:0'>
      <item id='31415926'>
        <bundle xmlns='urn:xmppqr:x3dhpq:bundle:0'>

          <!-- Device Certificate: AIK-signed binding of DIK to account -->
          <dc><<base64-device-certificate>></dc>

          <!-- DIK X25519 public key (32 bytes): base key in PQXDH -->
          <ik><<base64-x25519-dik-pubkey-32B>></ik>

          <!-- Signed Pre-Key (X25519, signed by DIK Ed25519) -->
          <spk id='5'>
            <key><<base64-x25519-spk-pubkey-32B>></key>
            <sig><<base64-dik-ed25519-sig>></sig>
          </spk>

          <!-- ML-KEM-768 pre-keys (1184 bytes each) -->
          <kemkeys>
            <kemkey id='1'><<base64-mlkem-768-pubkey-1184B>></kemkey>
            <kemkey id='2'><<base64-mlkem-768-pubkey-1184B>></kemkey>
            <!-- at least 5 SHOULD be published -->
          </kemkeys>

          <!-- X25519 One-Time Pre-Keys (32 bytes each) -->
          <opks>
            <opk id='1'><<base64-x25519-opk-pubkey-32B>></opk>
            <opk id='2'><<base64-x25519-opk-pubkey-32B>></opk>
            <!-- at least 10 SHOULD be published -->
          </opks>

        </bundle>
      </item>
    </publish>
  </pubsub>
</iq>
```

### 9.2. PQXDH Key Agreement

Session establishment follows the PQXDH protocol, adapted for the bundle format defined in Section 9.1. The initiating client (Alice) fetches the responder's (Bob's) bundle and performs:

**Step 1 — DC verification** (mandatory when peerAIK is known):

```
if peerAIK != nil:
    assert peer.DeviceCert.Verify(peerAIK) == nil   // abort if untrusted
```

**Step 2 — X25519 DH triples:**

```
dh1 = X25519(myDIK.PrivX25519,   peer.SPKPub)         // DIK_A vs SPK_B
dh2 = X25519(myEphemX25519Priv,  peer.IdentityPubX25519)  // EK_A vs IK_B
dh3 = X25519(myEphemX25519Priv,  peer.SPKPub)         // EK_A vs SPK_B
dh4 = X25519(myEphemX25519Priv,  opk.PubX25519)       // EK_A vs OPK_B (if OPK used)
```

**Step 3 — ML-KEM-768 encapsulation:**

```
(kemCiphertext, kemSS) = ML-KEM-768.Encaps(kemPreKey.PubMLKEM)
```

**Step 4 — Root key derivation:**

```
material = dh1 || dh2 || dh3 [|| dh4] || kemSS
rootKey  = HKDF-SHA-512(salt=<zero 64 bytes>, ikm=material, info="X3DHPQ-X3DH-PQ-v0")
           -> 64 bytes; first 32 = RK, second 32 = initial CK
```

**Step 5 — Associated data:**

```
AD = myDIK.PubX25519 || peer.IdentityPubX25519
```

The 64-byte `rootKey` is split 32||32 and passed to `NewSendingState` (initiator) or `NewReceivingState` (responder). The `AD` value is bound to every subsequent message (Section 9.4).

Bob's `RespondSession` mirrors this computation using `ML-KEM-768.Decaps(kemCiphertext, kemPreKeyPriv)` to recover the same `kemSS`, then reconstructs the identical `rootKey`.

### 9.3. AAD Computation

The AAD for AEAD encryption of each message is:

```
AAD = AD || MessageHeader.Marshal()
```

where `AD = initiator_DIK_PubX25519 || responder_DIK_PubX25519` and `MessageHeader` encodes the current DH ratchet state (see §9.4). Binding the AAD to both DIK X25519 public keys ensures that a session cannot be replayed between different device pairs.

### 9.4. Triple Ratchet State

After session establishment, messages are protected by the Triple Ratchet (`State` in `ratchet.go`):

```go
type State struct {
    RK                  []byte   // 32-byte root key
    ChainSendKey        []byte   // current sending chain key
    ChainRecvKey        []byte   // current receiving chain key
    SendingDH           PrivPub  // current sending DH keypair (X25519)
    RemoteDHPub         []byte   // most recent remote DH public key
    SendCount           uint32   // messages sent on current chain
    RecvCount           uint32   // messages received on current chain
    PrevSendCount       uint32

    KEMSendPub          []byte   // peer's KEM pub (we encapsulate to this next checkpoint)
    KEMRecvPriv         []byte   // our KEM priv (peer encapsulates to this)
    KEMRecvPub          []byte   // our KEM pub (advertised in headers)
    KEMSinceCheckpoint  uint32   // messages since last KEM checkpoint
    LastCheckpointTime  time.Time

    MessageKeys         map[SkipKey][]byte  // skipped-message-key cache (max 1000)
    AD                  []byte
}
```

The `MessageHeader` wire format (length-prefixed fields, big-endian uint32 lengths):

```
field DHPub           []byte   // 32-byte X25519 ratchet public key
field PrevChainLen    uint32
field N               uint32   // message number in current chain
field KEMCiphertext   []byte   // present only on KEM checkpoint messages (1088 bytes)
field KEMPubForReply  []byte   // our current KEM pub (1184 bytes) — always present when non-nil
```

#### 9.4.1. KEM Checkpoint Cadence

A KEM checkpoint fires on the sending side when:

- `KEMSinceCheckpoint >= 50` (counter threshold K = 50), OR
- `now - LastCheckpointTime >= 3600 seconds` (time threshold T = 1 hour) and a message is being sent.

When a checkpoint fires:
1. A fresh ML-KEM-768 keypair `(newKEMPub, newKEMPriv)` is generated.
2. The KEM ciphertext is computed: `(kemCT, kemSS) = ML-KEM-768.Encaps(KEMSendPub)`.
3. The root key and both chain keys are updated via the normative state transition in §5 (see "KEM checkpoint (Triple Ratchet)" subsection): `RK`, `ChainSendKey`, and `ChainRecvKey` are all replaced.
4. `kemCT` and `newKEMPub` are included in the message header.
5. The receiver decapsulates `kemSS` and applies the same state transition, assigning `CKs_new → ChainRecvKey` and `CKr_new → ChainSendKey` (roles are symmetric).

K = 50 and T = 3600 s are the spec values. After at most 50 messages or 1 hour of idle followed by a message, both the root key and all chain keys are healed. An attacker who holds the old RK but missed the `kem_ss` cannot recover RK_new or any subsequent message keys.

#### 9.4.2. Out-of-Order Delivery

The ratchet caches up to `maxSkipKeys = 1000` skipped message keys (indexed by DHPub string + message N). Replayed or out-of-window messages MUST be rejected.

---

## 10. Pairing (Typed Code + CPace PAKE)

Pairing allows a new device to enrol under the account's AIK without any contact interaction. It is a 9-step finite state machine running over the `urn:xmppqr:x3dhpq:pair:0` namespace.

### 10.1. Code Construction

The pairing code is 10 decimal digits: 9 random digits followed by a Luhn-mod-10 check digit.

```go
// GeneratePairingCode: read 9 random bytes, reduce each mod 10 to get digits,
// append Luhn check digit.
// FormatPairingCode: display as "DDD-DDD-DDD-C" (3-3-3-1 grouping).
```

Effective entropy: approximately 30 bits (10^9 possible 9-digit prefixes). This is sufficient because:
- CPace binds the code to the PAKE session — a wrong code produces an unrecoverable handshake failure with no partial information leak.
- The 60-second TTL combined with server-side stanza rate limiting bounds online attempts to at most a few per second per JID pair.

The Luhn check digit enables the UI to detect simple transcription errors before attempting the PAKE.

### 10.2. CPace Construction

x3dhpq uses CPace as defined in draft-irtf-cfrg-cpace-13, instantiated with X25519 and the Elligator2 hash-to-curve from RFC 9380 §6.7.2 (`curve25519_XMD:SHA-512_ELL2_NU_`, the single-field-element non-uniform variant). The generator point G is derived from the password and full transcript context via Elligator2, ensuring G has unknown discrete log with respect to the standard X25519 basepoint — the property CPace requires. The `_NU_` suite is used instead of `_RO_` because `_RO_` requires Curve25519 point addition (two Elligator2 evaluations followed by Montgomery-ladder point add), adding complexity with no security benefit for CPace — both variants produce a point with unknown DLOG.

**Transcript binding (`CI`):**

Both sides assemble an identical transcript before the PAKE exchange:

```
transcript = pack(
    "X3DHPQ-CPace-Transcript-v1\0",
    bare_jid,
    full_jid_initiator,
    full_jid_responder,
    server_domain,
    aik_pub_initiator (or empty),
    aik_pub_responder (or empty),
    0x49 ('I'),   // initiator role marker
    0x52 ('R'),   // responder role marker
    purpose,      // e.g. "device-pairing"
)
```

where `pack` uses `uint16-be(len) || bytes` length-prefixed concatenation for each field.

**Generator derivation (Elligator2 hash-to-curve):**

```
H2C_input = pack(PRS, sid, transcript)   // length-prefixed
G = hashToCurveX25519(H2C_input, "X3DHPQ-CPace-v1")
    // curve25519_XMD:SHA-512_ELL2_NU_ per RFC 9380 §6.7.2
```

**PAKE1 message (each party):** a 32-byte random scalar `y` (clamped per RFC 7748), `Y = X25519ScalarMult(y, G)`.

**Session key derivation (transcript-bound):**

```
K  = X25519ScalarMult(y, peer_Y)
ma, mb = lexicographic_min(Y_self, Y_peer), lexicographic_max(Y_self, Y_peer)
transcript_hash = SHA-512(
    "X3DHPQ-CPace-SessionTranscript-v1\0" ||
    uint16-be(sid_len)        || sid        ||
    uint16-be(transcript_len) || transcript ||
    uint16-be(len(ma))        || ma         ||
    uint16-be(len(mb))        || mb
)
PRK        = HKDF-Extract(salt=sid, ikm=K || transcript_hash)
sessionKey = HKDF-Expand(PRK, info="CPace-SessionKey-v1", len=32)
```

**Confirm tags (16 bytes each, asymmetric by role):**

```
PRK_c    = HKDF-Extract(salt=sid, ikm=sessionKey)
confirmA = HKDF-Expand(PRK_c, info="CPace-ConfirmA-v1" || sid, len=16)
confirmB = HKDF-Expand(PRK_c, info="CPace-ConfirmB-v1" || sid, len=16)
```

Initiator (Existing, E) uses role `CPaceInitiator`; responder (New, N) uses `CPaceResponder`.

Test vectors: see `internal/x3dhpqcrypto/cpace_test.go`. The `expand_message_xmd` subroutine is verified against the RFC 9380 DST and algorithm with known-good computed values. The RFC 9380 J.6 published test vectors target the `_RO_` (two-field-element) suite; this implementation uses `_NU_` (one field element) and includes computed vectors for cross-implementation verification. draft-irtf-cfrg-cpace-13 does not publish stable X25519 PAKE test vectors as of April 2026; `TestCPaceDraftVectors` is skipped pending their publication.

### 10.3. 9-Step FSM

The pairing protocol has two state machines: `PairingExisting` (E, the primary device displaying the code) and `PairingNew` (N, the new device entering the code). Both advance through the same `pairingStep` type.

#### Message types

| Type | Value | Direction | Content |
|------|-------|-----------|---------|
| `PairingMsgPAKE1` | 1 | E → N | PAKE Y-point (32 bytes) |
| `PairingMsgPAKE2` | 2 | N → E | PAKE Y-point (32 bytes) |
| `PairingMsgConfirm` | 3 | E → N and N → E | 16-byte HKDF confirm tag |
| `PairingMsgPayload` | 4 | N → E: DIK pub; E → N: issuance payload | AES-256-GCM ciphertext under sessionKey |
| `PairingMsgAck` | 5 | N → E | AES-256-GCM("ok") under sessionKey |

All `PairingMsg` wire encoding: `uint8(type) | uint32(payload_len) | <payload>`.

#### Step sequence

```
E (pairingStepInit)
  1. E.Step(nil)          → PairingMsgPAKE1(Y_E)    → N
  2.                      ← PairingMsgPAKE2(Y_N)    ← N.Step(PAKE1)
     E derives sessionKey; E.Step(PAKE2)
  3. E.Step(PAKE2)        → PairingMsgConfirm(tagE)  → N
  4.                      ← PairingMsgConfirm(tagN)  ← N.Step(Confirm_E)
     E verifies tagN; if ok: E.Step(Confirm_N) → nil (transitions to waitDIK)
  5. N sends DIK pub encrypted under sessionKey:
                          ← PairingMsgPayload(enc(DIKpub)) ← N.Step(nil)
  6. E decrypts DIK pub; issues DC; constructs issuance payload:
     E.Step(Payload_DIK) → PairingMsgPayload(enc(issuance)) → N
  7. N receives issuance payload; decrypts; stores AIK pub + DC [+ AIKpriv]:
                          ← PairingMsgAck(enc("ok")) ← N.Step(Issuance)
  8. E.Step(Ack) → nil, done=true
```

Total round trips: 4 (PAKE1/PAKE2, Confirm_E/Confirm_N, DIKpub/Issuance, Ack). Typical completion time: under 2 seconds on LAN; under 5 seconds over WAN.

AEAD nonces for the encrypted payloads are deterministic and role-separated:

```
encCounter nonce = roleTag(1 byte) | 0x000000(3 bytes) | uint64(counter, big-endian)
```

where roleTag is `'E'` for Existing-originated messages and `'N'` for New-originated messages.

### 10.4. State Transfer (Issuance Payload)

The issuance payload (encrypted under sessionKey, sent E → N) contains:

```
uint16  dc_len    | <DeviceCertificate.Marshal()>
uint16  aik_pub_len | <AccountIdentityPub.Marshal()>
uint8   has_priv   (1 if AIK_priv is being transferred, else 0)
uint16  aik_priv_len | <marshalled AIK_priv> (zero-length if has_priv=0)
uint32  state_blob_len | <state blob> (optional onboarding snapshot: roster, MAM cursors, etc.)
```

The state blob is implementation-defined. Its content is opaque to the protocol; clients SHOULD populate it with enough information to allow the new device to catch up without re-fetching everything from the server.

### 10.5. Failure Paths and Rate Limits

- **Wrong code**: CPace produces a different session key; the confirm tag verification (`VerifyConfirm`) fails. Both devices show "Invalid code". No retry counter increments on the account; rate limiting is purely at the stanza level.
- **Code TTL elapsed**: The primary device discards the pairing context. The UI shows "Code expired." The new device MUST abort without retrying automatically.
- **Server rate limiting**: The server SHOULD rate-limit pairing stanzas per (resource_from, resource_to) pair to slow online code-guessing. The server MUST NOT inspect pairing payload contents (opacity contract, Section 15.1).
- **New device unreachable**: The user retries with a fresh code on the primary.

---

## 11. Audit Chain

### 11.1. PEP Node and +notify

The audit chain is published on PEP node `urn:xmppqr:x3dhpq:audit:0`. Each `AuditEntry` is a separate PEP item (item id = decimal seq number). The node MUST be configured with `+notify` enabled. Contacts receive real-time notifications on each new entry.

The server SHOULD enforce a per-account item cap (suggested default: 1 MiB total encoded size; pruning policy is implementation-defined). The append-only guarantee is a client-enforced invariant; the server cannot prevent publishing a new chain, but clients detect forks via hash chain verification.

### 11.2. Entry Structure

```go
type AuditEntry struct {
    Seq       uint64       // 0-based, contiguous
    PrevHash  [32]byte     // SHA-256 of previous entry's Marshal(); zero for seq=0
    Action    AuditAction  // 1=add-device, 2=remove-device, 3=rotate-aik, 4=recover-from-backup
    Payload   []byte       // action-specific; see §11.4
    Timestamp int64        // unix seconds; MUST NOT be less than previous entry's timestamp
    Signature []byte       // Ed25519 signature by AIK over SignedPart
}
```

### 11.3. SignedPart and Hash Chaining

`AuditEntry.SignedPart()` produces:

```
"X3DHPQ-Audit-v1\x00" (16 bytes)
uint64  seq
[32]byte prevHash
uint8   action
uint32  payload_len | <payload>
int64   timestamp
```

`AuditEntry.Hash()` is `SHA-256(entry.Marshal())`, where `Marshal()` appends `uint16(sig_len) | <signature>` to `SignedPart()`.

### 11.4. Action Types and Payloads

| Action | Value | Payload encoding |
|--------|-------|-----------------|
| `AddDevice` | 1 | `uint32(device_id) | uint32(cert_len) | <DeviceCert.Marshal()>` |
| `RemoveDevice` | 2 | `uint32(device_id)` |
| `RotateAIK` | 3 | `uint16(new_aik_len) | <AccountIdentityPub.Marshal()>` |
| `RecoverFromBackup` | 4 | `int64(recovered_at) | uint16(device_count)` |

### 11.5. Verification — VerifyChain

`VerifyChain(entries []*AuditEntry, aikPub *AccountIdentityPub) error` implements:

1. For each entry at position `i`:
   - Verify `Ed25519Verify(aikPub.PubEd25519, entry.SignedPart(), entry.Signature)`.
   - Assert `entry.Seq == uint64(i)`.
   - If `i == 0`: assert `entry.PrevHash == [32]byte{}` (genesis entry).
   - If `i > 0`: assert `entry.PrevHash == entries[i-1].Hash()`.
   - Assert `entry.Timestamp >= entries[i-1].Timestamp` (monotonicity).

A chain that fails any check MUST be rejected. A partial chain (only the tail is fetched) can still be verified by anchoring on a previously stored hash.

### 11.6. UX Guidance for Clients

Clients SHOULD tail the audit chain on login and on each +notify event. For each new entry, the client SHOULD surface a notification:

- `AddDevice`: "Your account was used to add a new device `<device_id>` on `<timestamp>`. Was that you?"
- `RemoveDevice`: "A device was removed from your account."
- `RotateAIK`: "Your account's identity key has rotated. If this was not you, your primary device may be compromised."
- `RecoverFromBackup`: "Your account was recovered from a backup. `<device_count>` device(s) were re-authorized."

A compromised primary that silently adds itself to the account still produces an audit entry signed by the AIK. Detection is post-hoc but reliable as long as at least one legitimate device is watching the audit chain.

---

## 12. AIK Rotation

### 12.1. Rotation Pointer

When a user suspects their AIK_priv has been compromised, they initiate an AIK rotation. The rotation process:

1. Generate a new AIK keypair (`newAIK`).
2. Produce a `RotationPointer` signed by the old AIK:

```
SignedPart = "X3DHPQ-Rotation-v1\x00"
             | uint16(version=1)
             | uint16(old_aik_len) | <OldAIKPub.Marshal()>
             | uint16(new_aik_len) | <NewAIKPub.Marshal()>
             | int64(rotated_at)
             | uint16(reason_len) | <reason UTF-8> (max 512 bytes)
Signature = Ed25519Sign(oldAIK.PrivEd25519, SignedPart)
```

3. Append a `RotateAIK` entry to the audit chain (signed by the old AIK).
4. Re-issue DCs for all current devices under the new AIK (`ReissueDeviceCerts`).
5. Publish a new signed devicelist under the new AIK (version incremented).

`ApplyRotation(oldAIK, prev *AuditEntry, reason, timestamp)` in `aik_rotation.go` performs steps 1–3 and returns a `RotationResult` containing the pointer, new AIK, and audit entry.

### 12.2. Re-issuing Device Certificates

`newAIK.ReissueDeviceCerts(devices []DeviceReissueInput)` produces fresh DCs for each device, signed by the new AIK. Each DC has a new `created_at` timestamp. The device's `DIKPubX25519`, `DIKPubEd25519`, and `DIKPubMLDSA` are unchanged.

### 12.3. Trust Policy on Rotation Detection

When a contact observes a `RotateAIK` audit entry (via +notify), the following trust policies apply:

| Policy | Constant | Behavior |
|--------|----------|----------|
| Warn-accept (default) | `RotationTrustWarnAccept` | Verify rotation pointer signature; accept new AIK; require out-of-band re-verification; display warning. |
| Strict | `RotationTrustStrict` | Reject all messages from the rotated account until manual re-verification. |

`ShouldAcceptRotation(rp, policy)` returns `(accept bool, requireReverify bool, err error)`.

**Security note**: The rotation pointer itself is signed by the old AIK. An attacker who has compromised the old AIK can forge a rotation pointer. Therefore, even in warn-accept mode, out-of-band re-verification of the new AIK fingerprint SHOULD be performed before fully resuming encrypted communication.

### 12.4. Audit Chain Entry Semantics

The `RotateAIK` audit entry is signed by the **old** AIK, before it is retired. This provides the property: a legitimate rotation produces an entry signed by a key the contact already trusts. A rogue rotation that appears after a compromise is still detectable because the attacker must use the same (compromised) AIK to sign the entry — which confirms the compromise rather than hiding it.

---

## 13. Group Encryption (Sender Keys)

### 13.1. Membership Model

A group's encrypted membership is a **set of `AccountIdentityPub` (AIK public keys)**, not a set of device IDs. The `GroupSession` stores:

```go
type GroupMember struct {
    AIKPub    *AccountIdentityPub
    DeviceIDs []uint32
}
```

Each member's devices are populated from the PEP devicelist (Section 8). Trust evaluation for a device: the device's DC MUST be verified against the pinned AIK for that member. If valid, the device is included in the encryption set without any user prompt.

### 13.2. Per-Device Sender Chain

Each sender device maintains a `SenderChain` for each group it participates in:

```go
type SenderChain struct {
    Epoch      uint32
    ChainKey   []byte   // 32 bytes, randomly initialized per epoch
    NextIndex  uint32
    Skipped    map[uint32][]byte  // skipped message keys, max DefaultMaxSkipped=256
    MaxSkipped int
}
```

Chain key advancement follows the same HMAC-SHA-256 ratchet as the pairwise chain:

```
MK      = HMAC-SHA-256(ChainKey, 0x01)
CK_next = HMAC-SHA-256(ChainKey, 0x02)
```

### 13.3. Group Message Header

```go
type GroupMessageHeader struct {
    Version        uint16  // = 1
    Epoch          uint32
    SenderDeviceID uint32
    ChainIndex     uint32
}
// Wire: 14 bytes total
```

AEAD nonce for group messages: `"GMSG"(4) || epoch(4) || chainIndex(4)` (12 bytes).
AAD for group messages: `GroupMessageHeader.Marshal() || []byte(roomJID)`.

### 13.4. Sender Chain Announcements

When a device first sends in a group (or after an epoch rotation), it distributes its sender chain key to every recipient device via pairwise x3dhpq sessions. The `SenderChainAnnouncement` wire format:

```
uint16  version (= 1)
uint16  aik_pub_len | <SenderAIKPub.Marshal()>
uint32  sender_device_id
uint16  room_jid_len | <roomJID UTF-8>
uint32  epoch
uint32  chain_key_len (= 32) | <chain_key 32 bytes>
uint32  next_index
```

`GroupSession.AnnounceSenderChain()` produces the announcement from the current state. `GroupSession.AcceptSenderChain(ann)` verifies the sender is a current member (by AIK fingerprint match) and installs the chain into `RecvChains`.

Receiver chains are keyed by `recvKey{aikFP string, deviceID uint32, epoch uint32}`. An announcement from an unrecognized sender (not in `Members`) is rejected with `ErrAnnouncementUnknownSender`.

### 13.5. Epoch Rotation Triggers

An epoch rotation (`GroupSession.rotateEpoch()`) generates a new random `SenderChain` at `epoch+1`. Triggers:

1. **Member added** (`GroupSession.AddMember`): rotate immediately. The new member receives the new epoch's chain key after joining; they cannot decrypt messages sent before their arrival.
2. **Member removed** (`GroupSession.RemoveMember`): rotate immediately. The removed member has no chain key for the new epoch and cannot decrypt future messages.

**Current implementation note**: There is no automatic rotation by time or message count. Epoch rotation occurs only on membership change. This is a known limitation (see Section 20).

After rotation, the sender's `RecvChains` entries for removed members are deleted.

### 13.6. Forward Secrecy After Removal

When Bob is removed from a group and the epoch rotates, the new epoch's chain key is a freshly generated 32-byte random value — NOT derived from the previous chain key. Bob retains no information that helps him derive the new chain key. Therefore:

**Claim**: A removed member cannot decrypt any group message sent after the epoch rotation following their removal, even if they retained all previous keying material.

This is unconditional forward secrecy after removal, contingent on the epoch rotation being triggered before the next message is sent. The `RemoveMember` implementation immediately rotates, so the invariant holds as long as `RemoveMember` is called before any subsequent `Encrypt` call.

### 13.7. Out-of-Order Delivery

Each `SenderChain` caches up to `DefaultMaxSkipped = 256` skipped message keys. Received messages with `ChainIndex < sc.NextIndex` and not in the skipped cache are rejected with `ErrSenderChainPast`. Messages requiring caching beyond 256 skipped keys are rejected with `ErrSenderChainTooManySkipped`.

### 13.8. MUC Integration

For MUC rooms (XEP-0045), the encrypted group membership set SHOULD be maintained as an extension element in the room configuration or as a separate PEP node under the room's JID. Clients joining a MUC SHOULD:

1. Fetch the membership set (list of AIK fingerprints).
2. Verify each member's DC against the pinned AIK.
3. Exchange sender chain announcements with all member devices via pairwise sessions before sending.

Group presence extensions (informative):

```xml
<x xmlns='urn:xmppqr:x3dhpq:group:0'>
  <member aik-fp='A1B2C 3D4E5 F6A7B 8C9D0 E1F2A 3B4C5' jid='alice@example.org'/>
  <member aik-fp='B2C3D 4E5F6 A7B8C 9D0E1 F2A3B 4C5D6' jid='bob@example.org'/>
</x>
```

---

## 14. Recovery

### 14.1. Encrypted AIK Backup Blob

The AIK private key is sealed using a user-chosen passphrase via `SealAIK(aik, passphrase)`:

**KDF**: scrypt with N=131072, r=8, p=1 applied to the passphrase and a random 16-byte salt, producing a 32-byte KEK.

**Encryption**: AES-256-GCM with a random 12-byte nonce. AAD is the header string itself.

**Blob format** (a printable ASCII string):

```
x3dhpqv1$N=131072,r=8,p=1$<base64-salt>$<base64-nonce>$<base64-ciphertext>
```

Opening (`OpenAIK(blob, passphrase)`): the implementation enforces minimum security parameters (N >= 65536, r >= 8, p >= 1) before attempting decryption. A wrong passphrase produces `ErrRecoveryBadPassphrase`.

### 14.2. Paper Key Encoding

The sealed blob can be re-encoded as a human-readable paper key for offline storage:

```
X3DHPQ-AIK-V1
N=131072 r=8 p=1
<base32-salt>
<base32-nonce>
<base32-ciphertext in groups of 4, 8 groups per line>
```

Lines 3–4 encode the 16-byte salt (26 base32 chars) and 12-byte nonce (20 base32 chars). The ciphertext line(s) encode the AES-256-GCM output in uppercase base32 (RFC 4648 §6, no padding), grouped for readability.

`PaperKey(sealed string)` converts a blob to paper format. `PaperKeyDecode(paper string)` converts back. The paper key can be printed and stored physically; it is safe to store offline since the scrypt passphrase is not recorded with it.

### 14.3. Server-Side Storage

The sealed blob MAY be published as a PEP item at node `urn:xmppqr:x3dhpq:recovery:0` as a private (owner-only access, XEP-0060 §8.2.1) item with `id='current'`. The server MUST enforce the private node access model. This allows the user to retrieve the blob from any device logged into the account.

Informative XML example:

```xml
<iq type='set' from='alice@example.org/phone' id='pub-recovery-1'>
  <pubsub xmlns='http://jabber.org/protocol/pubsub'>
    <publish node='urn:xmppqr:x3dhpq:recovery:0'>
      <item id='current'>
        <recovery xmlns='urn:xmppqr:x3dhpq:recovery:0'>
          x3dhpqv1$N=131072,r=8,p=1$<<base64-salt>>$<<base64-nonce>>$<<base64-ct>>
        </recovery>
      </item>
    </publish>
    <publish-options>
      <x xmlns='jabber:x:data' type='submit'>
        <field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field>
        <field var='pubsub#access_model'><value>whitelist</value></field>
      </x>
    </publish-options>
  </pubsub>
</iq>
```

### 14.4. Threats This Mitigates and Does Not Mitigate

**Mitigates**:
- Loss of the primary device (phone broken, lost, stolen but locked) — user recovers the AIK from the backup blob using their passphrase on a fresh device.
- Total primary device destruction — same as above, if the blob was published to PEP or a paper key exists.

**Does not mitigate**:
- Passphrase-guessing by an adversary who obtains the blob (mitigated by scrypt parameters; user MUST choose a strong passphrase).
- Compromise of a device with an unencrypted or weakly-encrypted blob on disk.
- Compromise of the passphrase by a keylogger or memory-scraping attack.
- A server-side adversary who stores the private PEP item and mounts an offline brute-force — mitigated only by passphrase strength.

---

## 15. Server Behavior (Transport-Only)

### 15.1. Opacity Contract

The XMPP server is a transport layer only. It MUST NOT attempt to decrypt, parse, or inspect the content of:
- Any `<x3dhpq>` envelope (namespace `urn:xmppqr:x3dhpq:envelope:0`).
- Any pairing stanza (namespace `urn:xmppqr:x3dhpq:pair:0`).
- The `<recovery>` item body.
- The payload of any `<audit>` chain entry.

The server MUST treat these elements and all their children as opaque binary data, routing based solely on outer stanza addressing.

### 15.2. Per-Namespace Size Caps

The server MUST enforce a maximum byte size for PEP items and message envelopes:

```
ItemMaxBytes = 262144  // 256 KiB (default)
```

Items or envelopes exceeding this limit MUST be rejected with `<not-acceptable/>`. Implementers publishing large pre-key batches MUST verify they remain within this limit.

The audit chain PEP node has a separate cap:

```
AuditNodeMaxBytes = 1048576  // 1 MiB total (suggested default)
```

Rotation/pruning policy for the audit node when this cap is reached is implementation-defined; clients SHOULD store and verify the tail locally.

### 15.3. Pairing Rate Limiting

The server SHOULD rate-limit pairing stanzas (namespace `urn:xmppqr:x3dhpq:pair:0`) per (resource_from, resource_to) pair. Excessive pairing attempts SHOULD be rejected with `<policy-violation/>`. The pairing protocol itself (CPace) provides cryptographic protection against offline guessing; server-side rate limiting provides defense-in-depth.

### 15.4. Bundle Re-Publish Rate Limiting

To prevent denial-of-service via bundle flooding:

```
PublishesPerMinute = 1  // per device ID
```

Each device (identified by device ID) is limited to one bundle publish per minute. Excess publishes MUST be rejected with `<policy-violation/>`.

### 15.5. Disco Features

A server supporting this specification MUST advertise the following features in its service discovery (XEP-0030) response:

```xml
<feature var='urn:xmppqr:x3dhpq:0'/>
<feature var='urn:xmppqr:x3dhpq:devicelist:0+notify'/>
<feature var='urn:xmppqr:x3dhpq:audit:0+notify'/>
```

Additional namespace feature vars MAY be advertised at the operator's discretion.

The reference implementation (`internal/disco/features.go`) includes these in `DefaultServer()`.

Clients SHOULD check for `urn:xmppqr:x3dhpq:0` before publishing bundles or sending envelopes. A client connecting to a server that does not advertise this feature MAY fall back to OMEMO (Section 17) or MUST inform the user that post-quantum E2EE is unavailable.

### 15.6. x3dhpq-Only Mode (Per-Domain Policy)

A server MAY be configured to operate in x3dhpq-only mode, rejecting `<message>` stanzas that do not contain a `<x3dhpq>` envelope element.

When `DomainPolicy.X3DHPQOnlyMode` is `true`, any `<message>` stanza without a `<x3dhpq xmlns='urn:xmppqr:x3dhpq:envelope:0'>` child is rejected:

```xml
<message type='error' from='example.org' to='alice@example.org/phone'>
  <error type='modify'>
    <policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>
    <text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'>
      x3dhpq-only mode: an x3dhpq envelope is required
    </text>
  </error>
</message>
```

This is a domain-wide policy, not per-session negotiated. Legacy OMEMO-only clients cannot send messages on such a domain. Federation implications are discussed in Section 20.

---

## 16. Wire Format Sketches (Informative XML)

This section provides representative XML examples for each namespace. These sketches are informative; they show the logical structure and expected element names. Formal XSD/RNC schemas are deferred to Stable advancement.

### 16.1. Device List

See Section 8.4.

### 16.2. Bundle

See Section 9.1.1.

### 16.3. Pairwise Message Envelope

```xml
<message from='alice@example.org/phone'
         to='bob@example.org'
         type='chat'
         id='msg-001'>
  <x3dhpq xmlns='urn:xmppqr:x3dhpq:envelope:0'
          sender-device='31415926'
          ts='2026-04-30T12:00:00Z'>

    <!-- Per-recipient key blocks: one per recipient device -->
    <key rid='42424242'>
      <!-- MessageHeader (binary, base64-encoded): DHPub | PrevChainLen | N | [KEMCiphertext] | [KEMPubForReply] -->
      <hdr><<base64-message-header>></hdr>
      <!-- AES-256-GCM ciphertext of MK under per-device session -->
      <emk><<base64-encrypted-message-key>></emk>
    </key>

    <!-- PreKeyMessage fields (present only for session establishment) -->
    <prekey
        ek='<<base64-sender-ephemeral-x25519-pubkey-32B>>'
        opk-id='7'
        kemkey-id='3'
        kem-ct='<<base64-mlkem-768-ct-1088B>>'/>

    <!-- Encrypted payload: AES-256-GCM(plaintext, MK) -->
    <payload>
      <<base64-aes-256-gcm-ciphertext-with-gcm-tag>>
    </payload>

  </x3dhpq>
</message>
```

The `<payload>` is shared across all recipients; only the `<key>` blocks differ. The nonce for the payload AEAD is carried implicitly in the `MessageHeader` derivation path (via `deriveMessageKey`).

### 16.4. Pairing Messages

```xml
<!-- PAKE1: Existing device sends CPace Y-point -->
<message from='alice@example.org/desktop'
         to='alice@example.org/phone'
         type='chat' id='pair-1'>
  <pair xmlns='urn:xmppqr:x3dhpq:pair:0'
        type='pake1'
        sid='<<base64-session-id>>'>
    <<base64-cpace-y-point-32B>>
  </pair>
</message>

<!-- Issuance payload: Existing sends DC + AIK pub [+ optional AIK_priv] to New -->
<message from='alice@example.org/desktop'
         to='alice@example.org/phone'
         type='chat' id='pair-4'>
  <pair xmlns='urn:xmppqr:x3dhpq:pair:0'
        type='payload'
        sid='<<base64-session-id>>'>
    <<base64-aes-256-gcm-issuance-payload>>
  </pair>
</message>
```

### 16.5. Audit Chain Entry

```xml
<iq type='set' from='alice@example.org/desktop' id='pub-audit-1'>
  <pubsub xmlns='http://jabber.org/protocol/pubsub'>
    <publish node='urn:xmppqr:x3dhpq:audit:0'>
      <item id='3'>
        <audit-entry xmlns='urn:xmppqr:x3dhpq:audit:0'>
          <<base64-audit-entry-marshal>>
        </audit-entry>
      </item>
    </publish>
  </pubsub>
</iq>
```

### 16.6. Recovery Blob

See Section 14.3.

### 16.7. Group Sender-Chain Announcement

```xml
<message from='alice@example.org/phone'
         to='bob@example.org'
         type='chat'
         id='ann-001'>
  <x3dhpq xmlns='urn:xmppqr:x3dhpq:envelope:0' ...>
    <!-- sender-chain announcement is sent as the plaintext payload of a pairwise message -->
    <key rid='<<bob-device-id>>'>...</key>
    <payload>
      <!-- AES-256-GCM( SenderChainAnnouncement.Marshal() ) -->
      <<base64-encrypted-sender-chain-announcement>>
    </payload>
  </x3dhpq>
</message>
```

Sender chain announcements are wrapped in pairwise envelopes addressed to each recipient device individually. This ensures the announcement is authenticated (via the pairwise session AD) and confidential.

---

## 17. Coexistence with XEP-0384 OMEMO

x3dhpq-over-XMPP and OMEMO MAY coexist on the same server, unless the server is in x3dhpq-only mode (Section 15.6).

### 17.1. Feature Negotiation

A client supporting both SHOULD prefer x3dhpq-over-XMPP when both the sender and all intended recipient devices advertise `urn:xmppqr:x3dhpq:0`. Fallback to OMEMO is permissible when a recipient device does not support x3dhpq. When falling back, the client MUST clearly indicate to the user that the message is NOT protected against quantum adversaries.

### 17.2. Mixed Sessions

A single `<message>` stanza MUST NOT carry both a `<x3dhpq>` envelope and an OMEMO `<encrypted>` element. Senders MUST choose one protocol per message.

### 17.3. Session Isolation

x3dhpq session state and OMEMO session state are completely independent. They share no keying material, no ratchet state, and no pre-keys. A device supporting both protocols MUST maintain separate key stores for each.

### 17.4. Fall-Back Rules

Clients SHOULD implement the following fall-back order:

1. If both sender and all recipient devices advertise `urn:xmppqr:x3dhpq:0`: use x3dhpq (this spec).
2. If some recipient devices lack x3dhpq support: use OMEMO for those devices, x3dhpq for the rest. The message MUST be sent as two separate stanzas if both protocols are needed.
3. If no recipient device supports x3dhpq: use OMEMO and warn the user.
4. If the server is in x3dhpq-only mode: reject outgoing messages to devices that do not support x3dhpq; warn the user.

---

## 18. Security Considerations

### 18.1. Threat Model

The primary threat model is a **store-and-forward adversary** that:
- Records all XMPP traffic in transit and in server archives.
- Has access to a future CRQC sufficient to break X25519 and RSA.
- May compromise individual devices (but not all devices simultaneously).
- May control the XMPP server (honest-but-curious or actively malicious within the limits of PEP).

The protocol defends against:
- **HNDL attacks** (via ML-KEM-768 hybrid, §18.3).
- **Forward secrecy violations** (via ratchet chain key deletion, §18.2).
- **Post-compromise recovery** (via KEM checkpoints, §18.2).
- **Unauthorized device addition** (via AIK-signed DCs + audit chain, §18.4).
- **Bundle MITM by a passive server** (via AIK-bound DC signatures).

The protocol does **not** defend against:
- A malicious server substituting both the devicelist and the AIK public key simultaneously (requires key transparency, which is out of scope).
- Physical extraction of AIK_priv from a device with compromised hardware security.
- Traffic analysis (sender/recipient JIDs, message sizes, and timing are visible to the server).

### 18.2. Forward Secrecy and Post-Compromise Security

**Forward secrecy**: MessageKeys are derived from ChainKeys via a one-way function (HMAC-SHA-256). After a MessageKey is used and deleted, it cannot be re-derived from later ratchet state. Each DH ratchet step also overwrites the root key.

**Post-compromise security against a classical adversary**: the DH ratchet restores security after the first DH ratchet step following re-establishment with a party whose DH private key was not compromised.

**Post-compromise security against a quantum adversary** (CRQC capable of breaking X25519): the KEM checkpoints inject fresh ML-KEM-768 entropy. After at most K=50 messages or T=3600 seconds, the session key depends on `kemSS`, which a quantum adversary cannot derive without the ML-KEM-768 decapsulation key. Because ML-KEM-768 is believed to be quantum-secure, the quantum post-compromise window is bounded.

### 18.3. Hybrid PQ Security Argument

The root key derivation at session establishment:

```
material = dh1 || dh2 || dh3 [|| dh4] || kemSS
rootKey  = HKDF-SHA-512(salt=0, ikm=material, ...)
```

For `rootKey` to be distinguishable from random, an adversary must distinguish the entire `material` from random. If `kemSS` is computationally indistinguishable from random (ML-KEM-768 assumption — believed quantum-secure), then `material` is indistinguishable from random regardless of whether the adversary can break X25519. Symmetrically, if X25519 DH outputs are indistinguishable from random (classical assumption), `material` is indistinguishable even without the KEM. An adversary must break **both** primitives simultaneously.

This argument holds under the standard dual-PRF model for HKDF; see the PQXDH specification and hybrid KEM literature for formal treatment.

### 18.4. AIK Compromise and Rotation

If AIK_priv is compromised:
- The adversary can sign fake DCs and issue rogue devicelists.
- Detection is via audit chain monitoring (post-hoc).
- Recovery is via AIK rotation (Section 12), which produces a `RotateAIK` audit entry signed by the compromised AIK. This is detectable; contacts are warned.
- After rotation, contacts MUST re-verify the new AIK fingerprint out-of-band before resuming fully trusted communication.

### 18.5. Pairing Code Entropy and Online Attacks

The pairing code has approximately 30 bits of effective entropy (10^9 possible 9-digit prefixes). This entropy is sufficient under the following conditions:
- **CPace binding**: a wrong code produces a different session key; the confirm tag mismatch is an unrecoverable failure with no partial information.
- **60-second TTL**: after the TTL, the pairing context is discarded.
- **Rate limiting**: server-side stanza limits and per-(resource_from, resource_to) rate limits bound online attempts to at most a few per second.

Expected time to exhaust the search space online: at 10 attempts/second, 10^9 / 10 = 10^8 seconds ≈ 3 years. In practice, a single failed attempt (wrong code) causes the code to expire and a new code to be required, making systematic attacks impractical.

### 18.6. Group Forward Secrecy After Removal

See Section 13.6. The unconditional forward secrecy claim holds provided:
1. The removed member is not in possession of the new epoch's chain key (they are not, since it is freshly generated).
2. Epoch rotation occurs before the next outbound group message is sent.
3. The new epoch's chain key is distributed only to remaining members via pairwise sessions.

### 18.7. Side Channels and Constant-Time Requirements

Implementations MUST use constant-time implementations of all cryptographic primitives:
- ML-KEM-768 encapsulation and decapsulation MUST be constant-time.
- Ed25519 signing and verification MUST be constant-time.
- All secret key material MUST be zeroed from memory after use.

The xmppqr project uses wolfSSL/wolfCrypt for all cryptographic operations. wolfCrypt's ML-KEM and Ed25519 implementations are constant-time by design. Implementers using other libraries MUST verify the same property. In particular, ML-DSA-65 operations (when activated) MUST also be constant-time.

### 18.8. Recovery Passphrase Strength

The security of the AIK recovery blob depends entirely on passphrase strength when the blob is stored server-side. scrypt N=131072, r=8, p=1 provides approximately 128 MiB memory usage per attempt, which makes GPU/ASIC brute-force attacks expensive. However:
- A 4-word diceware passphrase (~51 bits entropy) is the practical minimum for server-stored blobs.
- An offline adversary who obtains the blob can mount a sustained brute-force attack; passphrase entropy is the only defense.
- Users who cannot maintain a strong passphrase SHOULD rely on paper-key offline storage combined with a physical security model instead.

---

## 19. Implementation Notes

### 19.1. Reference Implementation

The server-side and cryptographic reference implementation is:

```
github.com/danielinux/xmppqr
```

Relevant packages:

| Package | Contents |
|---------|----------|
| `internal/x3dhpqcrypto/` | All cryptographic types and operations (AIK, DIK, DC, devicelist, audit chain, PAKE, group, recovery, ratchet, PQXDH) |
| `internal/x3dhpq/` | Server-side namespace constants (`ns.go`), bundle validation, envelope validation, policy enforcement |
| `internal/disco/` | XEP-0030 service discovery feature advertisement |
| `internal/wolfcrypt/` | wolfSSL/wolfCrypt Go bindings (Ed25519, X25519, ML-KEM-768, HKDF, AES-GCM, HMAC, BLAKE2b, SHA-256, scrypt) |

### 19.2. Test Vectors

Package-level tests in `internal/x3dhpqcrypto/` cover:
- `TestDeviceCertRoundtrip` — DC marshal/unmarshal + verify.
- `TestDeviceListRoundtrip` — devicelist marshal/unmarshal + verify + rollback check.
- `TestAuditChainVerify` — audit chain append + VerifyChain.
- `TestPairingProtocol` — full 9-step PAKE FSM.
- `TestSenderChainSkip` — skipped-key handling in sender chains.
- `TestGroupSessionEpochRotation` — add/remove member with epoch rotation.
- `TestRecoverySeal` / `TestRecoveryPaperKey` — scrypt seal/open + paper key round-trip.
- `TestAIKRotation` — rotation pointer + ReissueDeviceCerts.
- `TestTripleRatchet` — pairwise Triple Ratchet with KEM checkpoints.

### 19.3. ML-DSA-65 Status

ML-DSA-65 (FIPS 204) is **not active** in the current implementation. All ML-DSA-65 fields in AIK, DIK, DC, and devicelist wire formats are zero-length. The wolfSSL build flag dependency (`WOLFSSL_DILITHIUM` or equivalent) has not been finalized. When activated in a future version:

- `AccountIdentityPub.PubMLDSA` will carry the 1952-byte ML-DSA-65 public key.
- `DeviceCertificate.MLDSASignature` will carry the 3309-byte ML-DSA-65 signature.
- All verification routines MUST require both Ed25519 and ML-DSA-65 signatures to pass.
- The `hasMLDSA = 1` flag in the AIK marshal encoding signals the presence of ML-DSA-65 material.
- Wire formats are forward-compatible: v1 parsers MUST tolerate nil ML-DSA-65 fields without error.

### 19.4. Cryptographic Library

xmppqr uses wolfSSL/wolfCrypt as its sole cryptographic backend. wolfCrypt provides:

| Function | wolfCrypt binding |
|----------|------------------|
| X25519 key generation | `wolfcrypt.GenerateX25519` |
| X25519 DH | `wolfcrypt.X25519SharedSecret` |
| X25519 scalar mult (CPace) | `wolfcrypt.X25519ScalarMult`, `wolfcrypt.X25519DerivePublic` |
| Ed25519 sign/verify | `wolfcrypt.Ed25519Sign`, `wolfcrypt.Ed25519Verify` |
| ML-KEM-768 encaps/decaps | `wolfcrypt.MLKEM768Encapsulate`, `wolfcrypt.MLKEM768Decapsulate` |
| HKDF-SHA-512 | `wolfcrypt.HKDFExtract`, `wolfcrypt.HKDFExpand` |
| HMAC-SHA-256 | `wolfcrypt.HMACSHA256` |
| AES-256-GCM | `wolfcrypt.NewAESGCM`, `.Seal`, `.Open` |
| BLAKE2b-160 | `wolfcrypt.Blake2b160` |
| SHA-256 | `wolfcrypt.SHA256` |
| SHA-512 | `wolfcrypt.SHA512` |
| scrypt | `wolfcrypt.Scrypt` |
| CSPRNG | `wolfcrypt.Read` |

Clients not using wolfCrypt MUST ensure their chosen library implements FIPS 203 (ML-KEM) as standardized, not pre-standardization draft versions.

---

## 20. Open Questions

The following questions are deferred and require resolution before this document can be advanced beyond Experimental status:

**OQ-1: x3dhpq-only mode and federation**
When a domain operates in x3dhpq-only mode, messages from federated domains that do not support x3dhpq will be rejected. Options: (a) x3dhpq-only mode applies only to intra-domain messages; (b) federated servers must negotiate x3dhpq capability before delivery is accepted; (c) per-remote-domain exception lists. No recommendation is made at this time.

**OQ-2: Anonymous group membership**
The current group design requires all members to know all other members' AIK fingerprints. Anonymous groups (membership privacy) are explicitly out of scope for v1. Possible approaches: anonymous credentials, private set intersection for member discovery.

**OQ-3: Cross-server account portability**
The current design assigns an AIK to a bare JID. Reusing the same AIK under a different JID (e.g., account migration) is not specified. This requires a cross-domain AIK-assertion mechanism that does not rely on the server.

**OQ-4: Group ratchet auto-rotation by time and message count**
The current implementation rotates the sender chain epoch only on membership change. There is no automatic rotation by time or message count. This creates a long-lived epoch if a group has stable membership — reducing post-compromise security. A default rotation interval (e.g., every 1000 messages or 24 hours) should be specified.

**OQ-5: Paper-key human factors**
The base32 ciphertext in the paper key encoding is long (variable; roughly 60–80 chars for the ciphertext alone). The grouping format (4-char groups, 8 per line) reduces transcription error probability, but no formal error-correction code is applied. Consider adding a checksum over the ciphertext portion.

**OQ-6: Server notification for low pre-key supply**
Clients must poll to detect low pre-key counts. A lightweight server-to-client notification (PEP event or specific IQ) for "pre-key supply below threshold" would be more efficient. The mechanism and triggering threshold are TBD.

**OQ-7: Inner plaintext envelope format**
The inner content of the `<payload>` AEAD is UTF-8 text for chat messages, but rich content (file transfers, reactions, replies, voice messages) requires a typed envelope. A structured inner format is not yet defined.

**OQ-8: Key transparency**
The current model trusts the server to deliver authentic devicelists and bundles. A malicious server can substitute these to perform MITM attacks. Key transparency (verifiable append-only log of bundle publications, similar to WhatsApp KT or Google KT) would mitigate this but adds significant complexity. Out of scope for v1.

---

## 21. References

### 21.1. Normative References

| Ref | Title | URL |
|-----|-------|-----|
| [FIPS-203] | FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM) | https://csrc.nist.gov/pubs/fips/203/final |
| [FIPS-204] | FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA) | https://csrc.nist.gov/pubs/fips/204/final |
| [RFC-7748] | Elliptic Curves for Security (X25519, X448) | https://www.rfc-editor.org/rfc/rfc7748 |
| [RFC-8032] | Edwards-Curve Digital Signature Algorithm (EdDSA) | https://www.rfc-editor.org/rfc/rfc8032 |
| [RFC-5869] | HMAC-based Extract-and-Expand Key Derivation Function (HKDF) | https://www.rfc-editor.org/rfc/rfc5869 |
| [RFC-7914] | The scrypt Password-Based Key Derivation Function | https://www.rfc-editor.org/rfc/rfc7914 |
| [RFC-7693] | The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC) | https://www.rfc-editor.org/rfc/rfc7693 |
| [RFC-6120] | Extensible Messaging and Presence Protocol (XMPP): Core | https://www.rfc-editor.org/rfc/rfc6120 |
| [RFC-6121] | Extensible Messaging and Presence Protocol (XMPP): Instant Messaging | https://www.rfc-editor.org/rfc/rfc6121 |
| [XEP-0060] | Publish-Subscribe | https://xmpp.org/extensions/xep-0060.html |
| [XEP-0163] | Personal Eventing Protocol | https://xmpp.org/extensions/xep-0163.html |

### 21.2. Informative References

| Ref | Title | URL |
|-----|-------|-----|
| [SIGNAL-SPQR-BLOG] | Signal: "PQXDH and the Sparse Post-Quantum Ratchet" | https://signal.org/blog/spqr/ |
| [SIGNAL-SPQR-CODE] | Signal: SparsePostQuantumRatchet (Rust reference implementation) | https://github.com/signalapp/SparsePostQuantumRatchet |
| [PQXDH] | The PQXDH Key Agreement Protocol | https://signal.org/docs/specifications/pqxdh/ |
| [CPACE] | CPace, a balanced composable PAKE | https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/ |
| [RFC-9382] | SPAKE2, a Password-Authenticated Key Exchange (for comparison) | https://www.rfc-editor.org/rfc/rfc9382 |
| [RFC-9420] | The Messaging Layer Security (MLS) Protocol | https://www.rfc-editor.org/rfc/rfc9420 |
| [XEP-0384] | OMEMO Encryption | https://xmpp.org/extensions/xep-0384.html |
| [XEP-0030] | Service Discovery | https://xmpp.org/extensions/xep-0030.html |
| [XEP-0045] | Multi-User Chat | https://xmpp.org/extensions/xep-0045.html |
| [XEP-0115] | Entity Capabilities | https://xmpp.org/extensions/xep-0115.html |
| [XEP-0313] | Message Archive Management | https://xmpp.org/extensions/xep-0313.html |
| [XEP-0334] | Message Processing Hints | https://xmpp.org/extensions/xep-0334.html |
| [DOUBLE-RATCHET] | The Double Ratchet Algorithm | https://signal.org/docs/specifications/doubleratchet/ |
| [WOLFSSL] | wolfSSL/wolfCrypt cryptographic library | https://www.wolfssl.com/ |
| [HPKE] | Hybrid Public Key Encryption (PQ KEM context) | https://datatracker.ietf.org/doc/rfc9180/ |

---

*End of XEP-XQR draft, version 0.2.0.*
