<!--
  SPDX-License-Identifier: AGPL-3.0-or-later
  xmppqr project — project-internal draft, not yet submitted to XSF
-->

| Field          | Value                                                      |
|----------------|------------------------------------------------------------|
| WIP Number     | XEP-XQR                                                    |
| Status         | Experimental (project-internal draft)                      |
| Type           | Standards Track                                            |
| Version        | 0.1.0                                                      |
| Last Updated   | 2026-04-30                                                 |
| Author         | xmppqr project                                             |
| License        | AGPLv3                                                     |
| Namespace      | urn:xmppqr:spqr:0                                          |
| Dependencies   | XEP-0163 (PEP), XEP-0060 (PubSub), RFC 6120/6121          |

---

# XEP-XQR: SPQR-over-XMPP (Sparse Post-Quantum Ratchet for XMPP End-to-End Encryption)

## 1. Abstract

This document specifies SPQR-over-XMPP, a protocol for end-to-end encrypted (E2EE) messaging on XMPP networks using the Sparse Post-Quantum Ratchet (SPQR) as defined by Signal. The protocol provides post-quantum confidentiality through a hybrid construction: every session combines classical X25519 Elliptic-Curve Diffie-Hellman with ML-KEM-768 (FIPS 203) key encapsulation to derive a shared root key. Long-term identity uses hybrid ML-DSA-65 + Ed25519 signatures. The result is a "Triple Ratchet" — Signal's Double Ratchet augmented with periodic KEM checkpoints — that retains both forward secrecy and post-compromise security under a quantum-capable adversary. The XMPP server is explicitly transport-only: it never holds keys, never decrypts content, and never inspects message envelopes.

---

## 2. Introduction

### 2.1. Motivation: post-quantum security for XMPP E2EE

Store-and-forward messaging networks such as XMPP are uniquely vulnerable to harvest-now-decrypt-later (HNDL) attacks. A nation-state adversary recording encrypted XMPP traffic today can attempt decryption once a sufficiently large cryptographically-relevant quantum computer (CRQC) becomes available. Because XMPP servers routinely archive messages (XEP-0313), and because forward-secrecy ratchets rotate keys only gradually, the exposure window can span years.

XEP-0384 OMEMO, the current XMPP E2EE standard, is based on Signal's Double Ratchet and X3DH. Both X25519 and the underlying AES-CBC+HMAC-SHA256 construction are secure against classical adversaries. However, the X3DH key agreement step and the Diffie-Hellman ratchet are broken by Shor's algorithm on a CRQC. OMEMO therefore provides no post-quantum security in its current form.

This specification addresses that gap. It ports Signal's Sparse Post-Quantum Ratchet (SPQR) — a Triple Ratchet construction that mixes a classical Double Ratchet with periodic ML-KEM-768 checkpoints — to XMPP wire format. The design ensures that compromise of either the classical or post-quantum component alone is insufficient to break message confidentiality.

### 2.2. Relation to OMEMO (XEP-0384) and Signal's SPQR

SPQR-over-XMPP shares OMEMO's broad approach: devices publish cryptographic bundles via PEP (XEP-0163 / XEP-0060), senders encrypt per-device keys, and the server routes opaque ciphertext. The key differences are:

1. **Initial key agreement**: X3DH is replaced by a post-quantum X3DH (PQXDH) variant that incorporates an ML-KEM-768 encapsulation step. The root key is derived from both an X25519 shared secret and a KEM shared secret.
2. **Ratchet**: Signal's Double Ratchet is augmented with a Sparse PQ Ratchet (SPQR). Every K messages (or after T seconds of inactivity), a fresh ML-KEM encapsulation checkpoint is injected into the root key derivation. This provides post-compromise security against a quantum adversary.
3. **Identity keys**: Long-term identity is represented as a hybrid keypair (Ed25519 || ML-DSA-65). Bundle signatures cover both.
4. **Server role**: OMEMO servers are already transport-only in theory; this specification makes that property explicit and defines server-enforced policies.

The ratchet semantics (state machine, message ordering, skip logic) are taken directly from Signal's reference Rust implementation at `github.com/signalapp/SparsePostQuantumRatchet`. This document re-binds the wire format to XMPP stanzas; implementers SHOULD consult that repository for ratchet internals not fully specified here.

---

## 3. Requirements

This document uses RFC 2119 key words. The following requirements shape the design:

- **REQ-1**: Message confidentiality MUST be maintained against both classical and quantum adversaries at the point of initial key agreement (HNDL resistance).
- **REQ-2**: The protocol MUST provide forward secrecy: compromise of current keying material MUST NOT enable decryption of past messages.
- **REQ-3**: The protocol MUST provide post-compromise security: after a device compromise, security MUST be automatically restored within at most K messages or T seconds (the KEM-checkpoint cadence), without user action.
- **REQ-4**: The server MUST NOT be able to decrypt any message or derive any session key.
- **REQ-5**: Clients that do not support SPQR-over-XMPP MUST be able to coexist on the same server without disruption.
- **REQ-6**: The protocol MUST be implementable using only NIST-standardized post-quantum primitives (FIPS 203, FIPS 204).
- **REQ-7**: Protocol overhead (bundle size, per-message overhead) MUST be bounded and documented.
- **REQ-8**: The protocol MUST NOT weaken security relative to XEP-0384 OMEMO if only classical algorithms are available (graceful hybrid degradation is out of scope; SPQR requires PQ).

---

## 4. Glossary

| Term | Definition |
|------|------------|
| **AEAD** | Authenticated Encryption with Associated Data |
| **ChainKey (CK)** | Symmetric key used to advance the sending or receiving chain |
| **CRQC** | Cryptographically-Relevant Quantum Computer |
| **DHR** | Diffie-Hellman Ratchet key pair (per-message ephemeral, classical X25519) |
| **Double Ratchet** | Signal's Double Ratchet Algorithm combining a KDF chain with a DH ratchet |
| **E2EE** | End-to-End Encryption |
| **HNDL** | Harvest-Now-Decrypt-Later — recording ciphertext for later quantum decryption |
| **IK** | Long-term Identity Key (hybrid Ed25519 + ML-DSA-65) |
| **KDF** | Key Derivation Function |
| **KEM** | Key Encapsulation Mechanism |
| **KEM-checkpoint** | A SPQR ratchet step that injects a fresh ML-KEM-768 shared secret into the root key |
| **ML-DSA-65** | Module-Lattice Digital Signature Algorithm (FIPS 204) at NIST security level 3 |
| **ML-KEM-768** | Module-Lattice Key Encapsulation Mechanism (FIPS 203) at NIST security level 3 |
| **MessageKey (MK)** | Ephemeral AEAD key derived from ChainKey for a single message |
| **OMEMO** | XEP-0384, the existing XMPP E2EE protocol based on Signal's Double Ratchet |
| **OPK** | One-Time Pre-Key (classical X25519) |
| **PEP** | Personal Eventing Protocol (XEP-0163 / XEP-0060) |
| **PQ** | Post-Quantum |
| **PQKEM-OPK** | One-Time Pre-Key KEM keypair (ML-KEM-768) |
| **PQSPK** | Signed Pre-Key for PQ KEM (ML-KEM-768, signed with IK) |
| **RootKey (RK)** | Top-level key from which ChainKeys are derived via KDF ratchet |
| **SPK** | Signed Pre-Key (classical X25519, signed with IK) |
| **SPQR** | Sparse Post-Quantum Ratchet — Signal's Triple Ratchet construction |
| **Triple Ratchet** | Double Ratchet + Sparse PQ Ratchet |
| **X3DH** | Extended Triple Diffie-Hellman (classical initial key agreement) |
| **PQXDH** | Post-Quantum Extended Triple Diffie-Hellman (Signal's PQ key agreement spec) |

---

## 5. Cryptographic Primitives

All cryptographic operations MUST use the following primitives. Implementations MUST NOT substitute weaker alternatives.

### 5.1. Asymmetric Primitives

| Primitive | Role | Reference |
|-----------|------|-----------|
| X25519 | Classical DH ratchet, SPK, OPK | RFC 7748 |
| Ed25519 | Classical component of hybrid identity signature | RFC 8032 |
| ML-KEM-768 | KEM component of PQXDH and SPQR checkpoints | FIPS 203 |
| ML-DSA-65 | PQ component of hybrid identity signature | FIPS 204 |

### 5.2. Symmetric Primitives

| Primitive | Role |
|-----------|------|
| HKDF-SHA-256 | All KDF operations (root key, chain key, message key, KEM mixing) |
| AES-256-GCM | AEAD encryption of message payload |
| HMAC-SHA-256 | Chain key advancement |

### 5.3. KDF Constructions

**Root key derivation (initial and DH ratchet steps):**

```
RK, CK = KDF_RK(RK, dh_out)
```

where `KDF_RK` is HKDF-SHA-256 with `RK` as the salt, `dh_out` as the input key material, and the fixed info string `"SPQR-RootKey-v0"`. Output is split 32 || 32 bytes.

**Hybrid root key derivation (PQXDH initial step and KEM-checkpoint steps):**

```
RK' = HKDF-SHA-256(
    salt  = RK,
    ikm   = X25519_ss || MLKEM768_ss,
    info  = "SPQR-HybridRoot-v0"
)
```

Both shared secrets are concatenated in the order `X25519_ss || MLKEM768_ss` before being passed as IKM. This construction ensures that knowledge of only one shared secret (either classical or PQ) is insufficient to derive `RK'`, provided HKDF's extraction step is collision-resistant. See Section 14.1 for the security argument.

**Chain key advancement:**

```
CK_next = HMAC-SHA-256(CK, 0x02)
MK      = HMAC-SHA-256(CK, 0x01)
```

**Message key expansion (AEAD key + nonce):**

```
AES_key || nonce = HKDF-SHA-256(
    salt  = <zero 32 bytes>,
    ikm   = MK,
    info  = "SPQR-MessageKey-v0",
    len   = 44   // 32-byte AES-256 key + 12-byte GCM nonce
)
```

### 5.4. Signature Construction

Identity bundle elements are signed with a hybrid signature: the signing operation produces two independent signatures over the same message, concatenated.

```
hybrid_sig = Ed25519_Sign(IK_ed, msg) || MLDSA65_Sign(IK_dsa, msg)
```

Verification requires both signatures to be valid. A bundle whose hybrid signature fails either component MUST be rejected.

### 5.5. Encoding

All binary cryptographic values appearing in XML MUST be encoded as standard Base64 (RFC 4648 § 4, with `=` padding). Whitespace within Base64 strings MUST be ignored by parsers.

---

## 6. Namespaces

| Namespace | Purpose |
|-----------|---------|
| `urn:xmppqr:spqr:0` | Root / disco feature |
| `urn:xmppqr:spqr:devicelist:0` | Device list PEP node |
| `urn:xmppqr:spqr:bundle:0` | Device bundle PEP node |
| `urn:xmppqr:spqr:envelope:0` | Message envelope element |

The namespace `urn:xmppqr:spqr:0` MUST be advertised in the server's service discovery features (XEP-0030) when the server supports this specification. See Section 11.4.

---

## 7. Identity, Devices, and Bundles

### 7.1. Device list (PEP)

Each XMPP account MAY have one or more devices. Each device is identified by a randomly generated, account-scoped, unsigned 32-bit integer `id`. Device IDs MUST be unique per account; a device MUST regenerate its ID if a collision is detected at publish time.

The device list is published as a PEP item at the node `urn:xmppqr:spqr:devicelist:0` with `item id='current'`.

```xml
<iq type='set' from='alice@example.org/phone' id='pub-dl-1'>
  <pubsub xmlns='http://jabber.org/protocol/pubsub'>
    <publish node='urn:xmppqr:spqr:devicelist:0'>
      <item id='current'>
        <devicelist xmlns='urn:xmppqr:spqr:devicelist:0'>
          <device id='31415926'/>
          <device id='27182818'/>
        </devicelist>
      </item>
    </publish>
  </pubsub>
</iq>
```

Clients MUST subscribe to the `urn:xmppqr:spqr:devicelist:0` PEP node of their own account and of every contact. A device that appears in the device list but has no corresponding bundle (Section 7.2) MUST be treated as unavailable for session establishment.

### 7.2. Device bundle (PEP)

Each device publishes a bundle at node `urn:xmppqr:spqr:bundle:0` with `item id` equal to the device ID (as a decimal string).

The bundle contains:

- **Identity key** (`<identity>`): the hybrid Ed25519 + ML-DSA-65 public key pair, concatenated and Base64-encoded.
- **Signed Pre-Key** (`<spk>`): a classical X25519 pre-key, with its ID and hybrid signature over the SPK public key.
- **PQ Signed Pre-Key** (`<pqspk>`): an ML-KEM-768 encapsulation public key, with its ID and hybrid signature.
- **One-Time Pre-Keys** (`<opks>`): a batch of classical X25519 one-time pre-keys.
- **PQ One-Time Pre-Keys** (`<pqopks>`): a batch of ML-KEM-768 one-time encapsulation keys.

```xml
<iq type='set' from='alice@example.org/phone' id='pub-bundle-1'>
  <pubsub xmlns='http://jabber.org/protocol/pubsub'>
    <publish node='urn:xmppqr:spqr:bundle:0'>
      <item id='31415926'>
        <bundle xmlns='urn:xmppqr:spqr:bundle:0'>

          <!-- Hybrid identity public key: 32 bytes Ed25519 || 1952 bytes ML-DSA-65 -->
          <identity>
            <<base64-ed25519-pubkey(32B) || mldsa65-pubkey(1952B)>>
          </identity>

          <!-- Signed Pre-Key (classical X25519) -->
          <spk id='1'>
            <key><<base64-x25519-spk-pubkey(32B)>></key>
            <!-- hybrid_sig over key bytes -->
            <sig><<base64-hybrid-sig>></sig>
          </spk>

          <!-- PQ Signed Pre-Key (ML-KEM-768 encapsulation key) -->
          <pqspk id='1'>
            <key><<base64-mlkem-768-pubkey(1184B)>></key>
            <!-- hybrid_sig over key bytes -->
            <sig><<base64-hybrid-sig>></sig>
          </pqspk>

          <!-- One-Time Pre-Keys (classical X25519), at least 10 SHOULD be published -->
          <opks>
            <opk id='1'><<base64-x25519-opk-pubkey(32B)>></opk>
            <opk id='2'><<base64-x25519-opk-pubkey(32B)>></opk>
            <!-- ... -->
          </opks>

          <!-- PQ One-Time Pre-Keys (ML-KEM-768), at least 10 SHOULD be published -->
          <pqopks>
            <pqopk id='1'><<base64-mlkem-768-pubkey(1184B)>></pqopk>
            <pqopk id='2'><<base64-mlkem-768-pubkey(1184B)>></pqopk>
            <!-- ... -->
          </pqopks>

        </bundle>
      </item>
    </publish>
  </pubsub>
</iq>
```

Clients MUST verify the `<sig>` elements before using any key material. The signature input is the raw binary key value (the Base64-decoded content of the `<key>` or `<pqopk>` child), not the XML text.

A device SHOULD replenish `<opks>` and `<pqopks>` when the server reports the supply is below a threshold (TBD: server signaling mechanism for low pre-key count is not yet defined; implementers may poll by fetching the bundle).

### 7.3. Bundle format (XML schema)

The following RelaxNG compact schema is informative:

```
namespace bundle = "urn:xmppqr:spqr:bundle:0"

start = element bundle:bundle {
  element bundle:identity { text } &
  element bundle:spk {
    attribute id { xsd:positiveInteger },
    element bundle:key { text },
    element bundle:sig { text }
  } &
  element bundle:pqspk {
    attribute id { xsd:positiveInteger },
    element bundle:key { text },
    element bundle:sig { text }
  } &
  element bundle:opks {
    element bundle:opk {
      attribute id { xsd:positiveInteger },
      text
    }+
  } &
  element bundle:pqopks {
    element bundle:pqopk {
      attribute id { xsd:positiveInteger },
      text
    }+
  }
}
```

### 7.4. Bundle size considerations

A bundle with 10 OPKs and 10 PQ-OPKs has an approximate unencoded binary footprint:

| Element | Size (bytes) |
|---------|-------------|
| Identity (Ed25519 + ML-DSA-65 pk) | 1984 |
| SPK (X25519 pk + hybrid sig) | 32 + 4627 ≈ 4659 |
| PQSPK (ML-KEM-768 pk + hybrid sig) | 1184 + 4627 ≈ 5811 |
| 10 × OPK (X25519) | 320 |
| 10 × PQOPK (ML-KEM-768) | 11840 |
| **Total (binary)** | **≈ 24.6 KiB** |
| **Total (Base64 in XML, ~1.37× overhead)** | **≈ 33.7 KiB** |

This is well within the server default `ItemMaxBytes` limit of 256 KiB (Section 11.2). Implementers choosing to publish larger pre-key batches MUST verify they remain within that limit.

The ML-DSA-65 signature size dominates. Switching to ML-DSA-44 (NIST level 2) would reduce the signature from 3309 bytes to 2420 bytes, with a corresponding reduction in security level. See Section 16 for the open trade-off discussion.

---

## 8. Session Establishment (X3DH-PQ / PQXDH)

Session establishment follows Signal's PQXDH specification, adapted for the XMPP bundle format defined in Section 7. The initiating client (Alice) fetches the responder's (Bob's) bundle and performs the following computation.

### 8.1. Inputs

Alice fetches Bob's bundle and extracts:
- `IK_B`: Bob's hybrid identity public key (Ed25519 || ML-DSA-65 components)
- `SPK_B` with id `spk_id`, and its hybrid signature `sig_spk`
- `PQSPK_B` (ML-KEM-768 encapsulation key) with id `pqspk_id`, and its hybrid signature `sig_pqspk`
- Optionally: `OPK_B` with id `opk_id` (X25519); `PQOPK_B` with id `pqopk_id` (ML-KEM-768)

Alice MUST verify both `sig_spk` and `sig_pqspk` against `IK_B` before proceeding. If verification fails, Alice MUST abort.

### 8.2. Alice's ephemeral keys

Alice generates:
- `EK_A`: fresh X25519 ephemeral key pair
- No client-side KEM encapsulation key is generated at this stage; the KEM operation runs in the other direction (Alice encapsulates to Bob's PQSPK/PQOPK).

### 8.3. Key agreement computation

```
dh1 = X25519(IK_A_priv, SPK_B)         // Alice's IK vs Bob's SPK
dh2 = X25519(EK_A_priv, IK_B_ed)       // Alice's EK vs Bob's IK
dh3 = X25519(EK_A_priv, SPK_B)         // Alice's EK vs Bob's SPK
dh4 = X25519(EK_A_priv, OPK_B)         // (if OPK present)

kem_ss_spk,  kem_ct_spk  = ML-KEM-768.Encaps(PQSPK_B)
kem_ss_opk,  kem_ct_opk  = ML-KEM-768.Encaps(PQOPK_B)   // (if PQOPK present)

classical_ss = dh1 || dh2 || dh3 [|| dh4]
pq_ss        = kem_ss_spk [|| kem_ss_opk]

RK = HKDF-SHA-256(
    salt  = <zero 32 bytes>,
    ikm   = classical_ss || pq_ss,
    info  = "SPQR-X3DH-PQ-v0"
)
```

The `||` operator denotes concatenation. Absent optional keys are simply omitted from the concatenation; the `info` string distinguishes the case.

The initial `RootKey` and first `ChainKey` are then split from `RK` output as per Section 5.3.

### 8.4. Alice's initial message (PreKeyMessage)

Alice MUST include the following in her first message envelope (see Section 10) so Bob can perform the corresponding computation:

- `IK_A` (or a reference to it via device ID)
- `EK_A` (Base64 X25519 public key)
- `spk_id` (the SPK ID used)
- `pqspk_id` (the PQSPK ID used)
- `kem_ct_spk` (ML-KEM-768 ciphertext, 1088 bytes)
- `opk_id` (if an OPK was used)
- `pqopk_id` (if a PQOPK was used)
- `kem_ct_opk` (ML-KEM-768 ciphertext, if PQOPK was used)

Bob reconstructs the same `RK` by computing the inverse DH operations and running `ML-KEM-768.Decaps` on the received ciphertexts.

### 8.5. One-time pre-key consumption

A PQOPK MUST NOT be reused. Bob MUST delete the PQOPK private key after decapsulation. A used PQOPK SHOULD be removed from the published bundle; failure to do so allows an attacker to replay the initial key agreement. Because the server cannot enforce PQOPK consumption (it is transport-only), clients bear responsibility for key hygiene.

---

## 9. Triple Ratchet

### 9.1. Double Ratchet refresher

After session establishment, messages are protected by Signal's Double Ratchet Algorithm. The Double Ratchet maintains:

- A **symmetric KDF chain** (sending chain and receiving chain), each advancing by one step per message. Each step produces a one-time `MessageKey (MK)` and advances the `ChainKey (CK)`.
- A **DH ratchet** that periodically refreshes the root key by performing a new X25519 DH exchange. Each side alternates: when Alice sends a ratchet-step message, she generates a new DHR key pair, performs DH with Bob's latest DHR public key, and derives a new `RootKey` and `ChainKey`.

This provides **forward secrecy**: past `MessageKey`s are deleted after use; a compromised current state does not expose past messages.

### 9.2. Sparse Post-Quantum Ratchet (SPQR)

The Sparse PQ Ratchet augments the Double Ratchet by injecting ML-KEM-768 shared secrets into the root key at intervals. The word "sparse" reflects that KEM operations are not performed on every message (unlike the DH ratchet in the Double Ratchet), because ML-KEM-768 ciphertexts (1088 bytes) and public keys (1184 bytes) are large relative to typical XMPP messages.

SPQR adds a **KEM ratchet state** alongside the DH ratchet state:

- `KEM_send_key`: the ML-KEM-768 encapsulation public key of the peer (available after the last KEM checkpoint).
- `KEM_recv_key`: the local ML-KEM-768 decapsulation private key pair for the current epoch.
- `kem_counter`: counts messages since the last KEM checkpoint.
- `kem_last_time`: timestamp of the last KEM checkpoint.

The detailed state machine is defined in the Signal SparsePostQuantumRatchet Rust reference implementation. This document specifies the XMPP wire binding and checkpoint cadence; implementers MUST follow the Rust implementation for state-machine semantics.

### 9.3. Mixing rule (Triple Ratchet)

When a KEM checkpoint fires (Section 9.4), the sender:

1. Generates a fresh ML-KEM-768 key pair `(kem_pk_new, kem_sk_new)`.
2. Encapsulates to the peer's current `KEM_send_key`: `(kem_ss, kem_ct) = ML-KEM-768.Encaps(KEM_send_key)`.
3. Derives a new root key:

```
RK_new, CK_new = KDF_RK_PQ(RK, dh_out, kem_ss)

KDF_RK_PQ(RK, dh_out, kem_ss) =
    HKDF-SHA-256(
        salt  = RK,
        ikm   = dh_out || kem_ss,
        info  = "SPQR-TripleRatchet-v0"
    )
    -> split 32 || 32 bytes
```

4. Sends `kem_ct` and `kem_pk_new` in the message header (see Section 10.2).
5. Updates local state: `RK = RK_new`, `CK = CK_new`, `KEM_recv_key = (kem_pk_new, kem_sk_new)`, resets `kem_counter`.

The receiver:

1. Runs `kem_ss = ML-KEM-768.Decaps(kem_ct, KEM_recv_sk)`.
2. Applies `KDF_RK_PQ` with the received `kem_ss` and the DH output from the concurrent DH ratchet step.
3. Updates `KEM_send_key = kem_pk_new` for the next checkpoint it initiates.

### 9.4. KEM-checkpoint cadence

A KEM checkpoint MUST be triggered when either of the following conditions is met:

- **Counter threshold**: `kem_counter >= K`, where **K = 50** (default). That is, at most every 50 messages, a KEM checkpoint is inserted.
- **Time threshold**: the elapsed time since the last KEM checkpoint exceeds **T = 3600 seconds** (1 hour), and a new message is being sent.

**Rationale**: K = 50 and T = 3600 s are chosen to balance post-compromise security restoration time against the overhead of including 1088-byte ML-KEM ciphertexts. After at most 50 messages or 1 hour of idle time followed by a message, a compromised ratchet state is automatically healed. These values are defaults; implementations MAY expose them as configurable parameters.

A KEM checkpoint message MUST include both the `kem_ct` (for the current checkpoint) and `kem_pk_new` (for the peer to use in the next checkpoint). Both fields appear in the `<key>` block of the envelope (Section 10.2).

---

## 10. Message Envelope

### 10.1. Envelope element

SPQR-over-XMPP messages are carried in XMPP `<message>` stanzas. The E2EE payload is contained in a `<spqr>` element in the `urn:xmppqr:spqr:envelope:0` namespace. The outer `<message>` stanza MAY carry a `<store/>` hint (XEP-0334) but MUST NOT carry a `<body/>` element when SPQR mode is active (Section 11.1).

```xml
<message from='alice@example.org/phone'
         to='bob@example.org'
         type='chat'
         id='msg-001'>
  <spqr xmlns='urn:xmppqr:spqr:envelope:0'
        sender_device='31415926'
        ts='2026-04-30T12:00:00Z'>

    <!-- Per-recipient key blocks: one per recipient device -->
    <key rid='42424242'
         spk_id='1'
         pqspk_id='1'>

      <!-- X25519 ephemeral key for this ratchet step (DH ratchet header) -->
      <dhr><<base64-x25519-dhr-pubkey(32B)>></dhr>

      <!-- Encrypted message key: AEAD(MK, per-device-key) -->
      <emk><<base64-encrypted-message-key>></emk>

      <!-- KEM checkpoint fields (present only when kem_counter >= K or time >= T) -->
      <kem_ct><<base64-mlkem-768-ciphertext(1088B)>></kem_ct>
      <kem_pk><<base64-mlkem-768-pubkey(1184B)>></kem_pk>

    </key>

    <!-- One-time pre-key identifiers (present only in PreKeyMessages) -->
    <prekey
        ik='<<base64-sender-identity-pubkey>>'
        ek='<<base64-sender-ephemeral-x25519-pubkey(32B)>>'
        opk_id='7'
        pqopk_id='3'
        kem_ct_spk='<<base64-mlkem-768-ct-for-pqspk(1088B)>>'
        kem_ct_opk='<<base64-mlkem-768-ct-for-pqopk(1088B)>>'/>

    <!-- Encrypted payload: AES-256-GCM(plaintext, MK) -->
    <payload iv='<<base64-gcm-nonce-12B>>'>
      <<base64-aes-256-gcm-ciphertext>>
    </payload>

  </spqr>
</message>
```

### 10.2. Per-recipient `<key>` blocks

Each `<key>` element encrypts the symmetric `MessageKey (MK)` for a single recipient device identified by `rid` (device ID). The `<emk>` element contains:

```
EMK = AES-256-GCM(
    key   = per_device_key,
    nonce = <zero 12 bytes>,   // nonce is implicit: MK is used only once
    pt    = MK || mac_key,     // 32 + 32 = 64 bytes
    aad   = sender_jid || sender_device_id || recipient_device_id
)
```

where `per_device_key` is derived from the shared ratchet state for that recipient device, and `mac_key` is the corresponding HMAC key for the payload (if used; may be folded into GCM tag).

The `<dhr>` element carries the sender's current DH ratchet public key (X25519, 32 bytes). The `<kem_ct>` and `<kem_pk>` elements are present only on KEM checkpoint messages. Their absence means no checkpoint fires on this message.

The attributes `spk_id` and `pqspk_id` on `<key>` are present only in the initial PreKeyMessage (`<prekey>` child present). After the session is established, they MAY be omitted.

### 10.3. AEAD payload

The `<payload>` element contains the AES-256-GCM ciphertext of the plaintext message content. The nonce is the 12-byte GCM nonce, carried as `iv` attribute (Base64-encoded). The `MessageKey` and nonce are derived as specified in Section 5.3.

The plaintext structure inside `<payload>` is a self-describing container (TBD: exact inner content encoding — UTF-8 text, or a structured envelope supporting typed content such as file transfers — is deferred to a later revision). At minimum, the plaintext MUST be a valid UTF-8 string for text messages.

The `<payload>` element is shared across all recipients; only the `<key>` blocks differ. This is the same "sealed sender" model used by OMEMO.

---

## 11. Server Behavior (Transport)

### 11.1. Opacity contract

The XMPP server is a transport layer. It MUST NOT attempt to decrypt, parse, or inspect the content of any `<spqr>` envelope. The server MUST treat the `<spqr>` element and all its children as opaque binary data, routing it based solely on the outer stanza addressing (`to`/`from` attributes).

This is enforced at the implementation level in `internal/spqr/envelope.go`: `ValidateEnvelope` checks only that the root element is `<spqr>` with the correct namespace and that the payload size is within bounds. No further parsing of envelope contents is performed.

### 11.2. PEP item size limits

The server MUST enforce a maximum byte size for PEP items published to SPQR nodes. The default limit is:

```
ItemMaxBytes = 262144  // 256 KiB
```

This limit is enforced by `internal/spqr/bundle.go:ValidateBundle`, which is called at publish time for items in the `urn:xmppqr:spqr:bundle:0` node. Items exceeding this limit MUST be rejected with an appropriate XMPP error stanza (SHOULD use `<not-acceptable/>` with a descriptive `<text>` element).

The same limit applies to `<spqr>` envelopes carried in `<message>` stanzas, enforced by `ValidateEnvelope`.

### 11.3. Bundle re-publish rate limiting

To prevent denial-of-service via bundle flooding, the server enforces a per-device publish rate limit:

```
PublishesPerMinute = 1  // per device ID
```

This is implemented by `internal/spqr/bundle.go:RateChecker`. Each device (identified by device ID) is limited to one bundle publish per minute. Attempts to publish more frequently MUST be rejected with `<policy-violation/>`.

The rate limit is applied per device key (device ID string), tracked in memory with a sliding window. The limit resets after 60 seconds have elapsed since the last allowed publish.

### 11.4. Disco feature `urn:xmppqr:spqr:0`

A server supporting this specification MUST advertise the feature `urn:xmppqr:spqr:0` in its service discovery (XEP-0030) response.

```xml
<!-- Server disco#info response (fragment) -->
<feature var='urn:xmppqr:spqr:0'/>
```

Clients SHOULD check for this feature before publishing SPQR bundles or sending SPQR envelopes. A client connecting to a server that does not advertise this feature MAY fall back to OMEMO (XEP-0384) or MUST inform the user that post-quantum E2EE is unavailable.

### 11.5. SPQR-only mode (per-domain policy)

A server MAY be configured to operate in SPQR-only mode, rejecting `<message>` stanzas that do not contain a `<spqr>` envelope.

This is implemented by `internal/spqr/policy.go:EnforceMessagePolicy`. When `DomainPolicy.SPQROnlyMode` is `true`, any `<message>` stanza that does not contain a `<spqr xmlns='urn:xmppqr:spqr:envelope:0'>` child element at depth 2 is rejected. The server returns a `<policy-violation/>` error:

```xml
<message type='error' from='example.org' to='alice@example.org/phone'>
  <error type='modify'>
    <policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>
    <text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'>
      SPQR-only mode requires a SPQR envelope
    </text>
  </error>
</message>
```

SPQR-only mode is a domain-wide policy and is NOT negotiated per-session. Clients connecting to a server with SPQR-only mode MUST support this specification; legacy OMEMO-only clients will not be able to send messages on such a domain.

Federation implications of SPQR-only mode are discussed in Section 16.

---

## 12. Client Discovery and Capability Negotiation

### 12.1. Capability advertisement

A client supporting SPQR-over-XMPP MUST advertise the feature `urn:xmppqr:spqr:0` in its entity capabilities (XEP-0115) and in its disco#info response.

```xml
<iq type='result' from='alice@example.org/phone' id='caps-1'>
  <query xmlns='http://jabber.org/protocol/disco#info'>
    <feature var='urn:xmppqr:spqr:0'/>
    <!-- Other features... -->
  </query>
</iq>
```

### 12.2. Bundle availability check

Before initiating a SPQR session with a contact, a client MUST:

1. Verify the server advertises `urn:xmppqr:spqr:0` (Section 11.4).
2. Fetch the contact's device list from `urn:xmppqr:spqr:devicelist:0`.
3. For each device, fetch the bundle from `urn:xmppqr:spqr:bundle:0`.
4. Verify the bundle signature (Section 7.2).

A session MUST NOT be established to a device whose bundle is absent or whose bundle signature fails verification.

### 12.3. Multi-device handling

When Alice sends a message to Bob, who has N devices, Alice MUST encrypt the message for all N of Bob's active devices. Alice MUST ALSO encrypt the message for all of her own other devices (to enable multi-device read receipts and conversation sync). Each device gets its own `<key rid='...'>` block in the envelope.

### 12.4. Unknown devices

If Alice discovers a new device in Bob's device list after a session has already been established, Alice MUST initiate a new SPQR session with that device before sending it messages. Alice MAY send a device-addressed probe message (carrying no user-visible content) to establish the session.

---

## 13. Coexistence with XEP-0384 OMEMO

SPQR-over-XMPP and OMEMO MAY coexist on the same server, unless the server operates in SPQR-only mode (Section 11.5).

### 13.1. Feature negotiation

A client that supports both SPQR-over-XMPP and OMEMO SHOULD prefer SPQR-over-XMPP when both the sender and all recipient devices advertise `urn:xmppqr:spqr:0`. Fallback to OMEMO is permissible when a recipient device does not support SPQR-over-XMPP.

When falling back to OMEMO, the client MUST clearly indicate to the user that the message is NOT protected against quantum adversaries.

### 13.2. Mixed sessions

A single `<message>` stanza MUST NOT carry both a `<spqr>` envelope (this spec) and an OMEMO `<encrypted>` element (XEP-0384). Senders MUST choose one protocol per message.

### 13.3. Session isolation

SPQR session state and OMEMO session state are completely independent. They share no keying material, no ratchet state, and no pre-keys. A device that supports both protocols MUST maintain separate key stores for each.

---

## 14. Security Considerations

### 14.1. Hybrid security argument

The root key derivation (Section 5.3) uses:

```
RK' = HKDF-SHA-256(salt=RK, ikm=X25519_ss || MLKEM768_ss, info=...)
```

The security of this construction rests on the following argument: HKDF's extraction step (HMAC-SHA-256 with the previous RK as salt) is a pseudorandom function (PRF). For the output `RK'` to be distinguishable from random, an adversary must distinguish the IKM from random. If X25519_ss is computationally indistinguishable from random (classical hardness assumption), or if MLKEM768_ss is computationally indistinguishable from random (PQ hardness assumption), then the IKM concatenation is indistinguishable from random, and HKDF output is pseudorandom.

Therefore: compromise of EITHER X25519 OR ML-KEM-768 alone is insufficient to derive `RK'`. An adversary needs to break BOTH.

This mitigates the HNDL threat: a quantum adversary who can break X25519 but cannot break ML-KEM-768 (which is believed to be quantum-secure) cannot decrypt recorded XMPP sessions.

**Note**: This argument assumes HKDF-SHA-256 behaves as a PRF when one of its IKM components is known. This is a standard assumption in hybrid KEM constructions; see the PQXDH specification and the academic literature on hybrid key exchange for formal analysis.

### 14.2. Forward secrecy and post-compromise security

**Forward secrecy** is provided by the symmetric KDF chain of the Double Ratchet. MessageKeys are derived from ChainKeys by a one-way function (HMAC-SHA-256). After a MessageKey is used and deleted, it cannot be re-derived from later state. Similarly, each DH ratchet step overwrites the root key, providing forward secrecy at the session level.

**Post-compromise security (PCS)** against a classical adversary is provided by the DH ratchet: after a compromise, the first DH ratchet step (triggered by the next reply from the non-compromised party) restores security, because the attacker does not know the new ephemeral X25519 private key.

**Post-compromise security against a quantum adversary** is provided by the SPQR KEM checkpoints. Every K messages or T seconds, a fresh ML-KEM-768 encapsulation injects fresh entropy from the non-compromised party's KEM key pair. After the checkpoint, the session key is derived from `kem_ss`, which the attacker cannot derive without the decapsulation key. Thus, even if a quantum adversary had full session state at time t, security is restored within K messages or T seconds.

The formal security analysis of the SPQR construction is provided by Signal in the SparsePostQuantumRatchet repository and associated documentation. This document relies on that analysis; implementers SHOULD review it.

### 14.3. Out-of-order delivery and replay

XMPP delivery is not guaranteed to be in order. The Double Ratchet handles out-of-order delivery by caching skipped MessageKeys (up to a configurable limit). This specification inherits that behavior.

Replay attacks are mitigated by the fact that MessageKeys are single-use and deleted after decryption. A replayed message that uses an already-consumed MessageKey MUST be rejected by the receiver. Implementers MUST track consumed MessageKeys for the duration of the message-skip window.

The maximum number of skipped MessageKeys that a receiver will cache SHOULD be bounded (suggested default: 1000) to prevent memory exhaustion attacks.

### 14.4. Threat model: server-honest-but-curious

The XMPP server is assumed to be **honest-but-curious**: it correctly routes messages, but it logs and analyzes all traffic it can observe. The protocol is designed to ensure that even under this threat model, the server learns nothing about message contents.

The server observes:
- Sender and recipient JIDs (traffic metadata)
- Message timestamps and sizes
- Whether messages carry `<spqr>` envelopes (yes/no)
- PEP bundle publications (public keys, but not private keys)

The server does NOT observe:
- Plaintext message content
- Message keys or ratchet state
- Session establishment shared secrets

A stronger threat model — a **malicious server** that actively modifies bundles — is partially addressed by bundle signatures (Section 7.2). A malicious server could substitute bundles with attacker-controlled keys, enabling a man-in-the-middle attack. Clients MUST verify bundle signatures; however, since the signing keys are also published via the same server, this only prevents passive MITM, not an active server replacing both bundle and signing key simultaneously.

Key transparency mechanisms (e.g., verifiable logs of bundle publications) are out of scope for this version. See Section 16.

### 14.5. Key compromise impersonation

In classical X3DH, if Alice's long-term identity key is compromised, an attacker can impersonate Alice to Bob by signing a fake SPK with Alice's stolen key. The same applies here to the Ed25519 component.

ML-DSA-65 provides a quantum-secure signature; an attacker with only a CRQC cannot forge ML-DSA-65 signatures. However, both components of the hybrid signature must be forged for a successful impersonation. Thus, key compromise impersonation via the ML-DSA-65 component requires a classical break of ML-DSA-65 (believed infeasible) or possession of the ML-DSA-65 private key.

Clients MUST implement key fingerprint verification (out-of-band) to detect long-term key changes. Unexplained identity key changes SHOULD be surfaced to the user as a security warning.

### 14.6. Side channels and constant-time requirements

Implementations MUST use constant-time implementations of all cryptographic primitives to prevent timing side channels. In particular:

- ML-KEM-768 decapsulation MUST be constant-time with respect to the decapsulation key and ciphertext.
- ML-DSA-65 signing and verification MUST be constant-time.
- All secret key material MUST be zeroed (securely erased) from memory after use.

The xmppqr project uses wolfSSL/wolfCrypt for all cryptographic primitives. wolfCrypt's ML-KEM and ML-DSA implementations are constant-time by design; implementers using other libraries MUST verify the same property.

---

## 15. Implementation Notes

### 15.1. Server-side reference implementation

The xmppqr server provides the reference implementation of the server-side components of this specification. The relevant package is `internal/spqr/`:

- `ns.go`: namespace constants (`NSRoot`, `NSBundle`, `NSDeviceList`, `NSEnvelope`).
- `bundle.go`: `ValidateBundle` (size and structure checking), `RateChecker` (rate limiting), `DefaultLimits`.
- `envelope.go`: `ValidateEnvelope` (size and namespace checking).
- `policy.go`: `EnforceMessagePolicy` (SPQR-only mode enforcement).

The server does not implement ratchet state or cryptographic operations; these are entirely client-side.

### 15.2. Ratchet reference implementation

The authoritative implementation of the Triple Ratchet state machine is Signal's Rust library at `github.com/signalapp/SparsePostQuantumRatchet`. Client implementers SHOULD study that codebase, particularly:

- The `SparsePostQuantumRatchet` struct and its state transitions.
- The KEM checkpoint trigger logic.
- The message key skipping and out-of-order handling.
- The handling of `PreKeyMessage` vs. regular `Message` types.

This document provides the XMPP wire binding; the Rust library provides the cryptographic and state-machine semantics. In any conflict between this document's description of ratchet internals and the Rust reference, the Rust reference takes precedence.

### 15.3. Cryptographic library

xmppqr uses wolfSSL/wolfCrypt as its cryptographic backend. wolfCrypt provides:
- `wc_MlKemKey` for ML-KEM-768 operations.
- `wc_MlDsaKey` for ML-DSA-65 operations.
- `wc_curve25519` for X25519.
- `wc_ed25519` for Ed25519.
- `wc_HKDF` for HKDF-SHA-256.
- `wc_AesGcmEncrypt`/`wc_AesGcmDecrypt` for AES-256-GCM.

Clients not using wolfCrypt MUST ensure their chosen library supports FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) as standardized, not pre-standardization draft versions.

### 15.4. Key storage

Client implementations MUST store private key material in encrypted form at rest. The following key types require secure storage:
- Long-term identity private key (Ed25519 + ML-DSA-65)
- SPK private key (X25519)
- PQSPK private key (ML-KEM-768 decapsulation key)
- OPK private keys (X25519)
- PQOPK private keys (ML-KEM-768 decapsulation keys)
- Active session ratchet state (root key, chain keys)

Pre-key private keys that have been consumed MUST be securely erased.

### 15.5. Bundle replenishment

Clients SHOULD monitor their published bundle and replenish one-time pre-keys when the supply falls below a threshold (suggested: 5 remaining OPKs or PQOPKs). The PEP mechanism does not provide a server-to-client notification for low pre-key count; clients MUST implement their own polling strategy (TBD: a server-side notification mechanism may be added in a future revision).

---

## 16. Open Questions

The following questions are deferred and require resolution before this document can be advanced beyond Experimental status:

**OQ-1: SPQR-only mode and federation**
When a domain operates in SPQR-only mode, messages arriving from federated domains that do not support SPQR-over-XMPP will be rejected by `EnforceMessagePolicy`. The correct behavior is unclear: should the server silently drop these messages, return an error to the sending server, or maintain a per-domain exception list? A hard reject may break federation with the majority of existing XMPP servers. Options include: (a) SPQR-only mode applies only to intra-domain messages; (b) federated servers are required to negotiate SPQR capability before message delivery is accepted; (c) a per-remote-domain exception list is maintained by the server operator. No recommendation is made at this time.

**OQ-2: Group messaging (MUC)**
Multi-User Chat (MUC, XEP-0045) and MUC Lite scenarios require key distribution to a dynamically changing set of participants. The pairwise session model of the Triple Ratchet does not directly extend to groups. Signal's approach (Sender Keys) is one option; the MLS protocol (RFC 9420) is another. Group SPQR is out of scope for this version. A future XEP-XQR-MUC document will address this.

**OQ-3: Key transparency and verifiable bundles**
The current model trusts the server to deliver authentic bundles. A malicious server can substitute bundles to perform MITM attacks against sessions being established for the first time. Key transparency (e.g., a Merkle-tree audit log of bundle publications, similar to Key Transparency as used in WhatsApp or Google's KT) would mitigate this threat but adds significant protocol and infrastructure complexity. This is out of scope for version 0.1.

**OQ-4: ML-DSA-65 vs ML-DSA-44 trade-off**
The identity signature uses ML-DSA-65 (NIST security level 3). ML-DSA-44 (NIST security level 2) would reduce the public key from 1952 bytes to 1312 bytes and the signature from 3309 bytes to 2420 bytes, saving approximately 1.5 KiB per bundle. The security difference between level 2 and level 3 is not fully characterized for the HNDL threat model; level 3 is chosen conservatively. Whether level 2 is acceptable given the bundle size savings should be revisited when the post-quantum threat landscape is better understood.

**OQ-5: Inner plaintext envelope format**
Section 10.3 defers the definition of the inner plaintext structure inside `<payload>`. At minimum it is UTF-8 text for chat messages, but rich content (file transfers, reactions, replies, voice messages) requires a typed envelope. A structured inner format (possibly reusing existing XMPP stanza fragments) needs to be specified.

**OQ-6: Server notification for low pre-key supply**
Section 15.5 notes that clients must poll to detect low pre-key counts. A lightweight server-to-client notification (e.g., a PEP event or a specific IQ) would be more efficient. The mechanism and triggering threshold are TBD.

---

## 17. References

### 17.1. Normative references

| Ref | Title | URL |
|-----|-------|-----|
| [FIPS-203] | FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM) | https://csrc.nist.gov/pubs/fips/203/final |
| [FIPS-204] | FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA) | https://csrc.nist.gov/pubs/fips/204/final |
| [RFC-7748] | Elliptic Curves for Security (X25519, X448) | https://www.rfc-editor.org/rfc/rfc7748 |
| [RFC-8032] | Edwards-Curve Digital Signature Algorithm (EdDSA) | https://www.rfc-editor.org/rfc/rfc8032 |
| [RFC-5869] | HMAC-based Extract-and-Expand Key Derivation Function (HKDF) | https://www.rfc-editor.org/rfc/rfc5869 |
| [RFC-6120] | Extensible Messaging and Presence Protocol (XMPP): Core | https://www.rfc-editor.org/rfc/rfc6120 |
| [RFC-6121] | Extensible Messaging and Presence Protocol (XMPP): Instant Messaging | https://www.rfc-editor.org/rfc/rfc6121 |
| [XEP-0060] | Publish-Subscribe | https://xmpp.org/extensions/xep-0060.html |
| [XEP-0163] | Personal Eventing Protocol | https://xmpp.org/extensions/xep-0163.html |

### 17.2. Informative references

| Ref | Title | URL |
|-----|-------|-----|
| [SIGNAL-SPQR-BLOG] | Signal: "PQXDH and the Sparse Post-Quantum Ratchet" | https://signal.org/blog/spqr/ |
| [SIGNAL-SPQR-CODE] | Signal: SparsePostQuantumRatchet (Rust reference implementation) | https://github.com/signalapp/SparsePostQuantumRatchet |
| [PQXDH] | The PQXDH Key Agreement Protocol | https://signal.org/docs/specifications/pqxdh/ |
| [RFC-9420] | The Messaging Layer Security (MLS) Protocol | https://www.rfc-editor.org/rfc/rfc9420 |
| [XEP-0384] | OMEMO Encryption | https://xmpp.org/extensions/xep-0384.html |
| [XEP-0030] | Service Discovery | https://xmpp.org/extensions/xep-0030.html |
| [XEP-0115] | Entity Capabilities | https://xmpp.org/extensions/xep-0115.html |
| [XEP-0313] | Message Archive Management | https://xmpp.org/extensions/xep-0313.html |
| [XEP-0334] | Message Processing Hints | https://xmpp.org/extensions/xep-0334.html |
| [XEP-0438] | Fall Back Indication (password storage best practices) | https://xmpp.org/extensions/xep-0438.html |
| [DOUBLE-RATCHET] | The Double Ratchet Algorithm | https://signal.org/docs/specifications/doubleratchet/ |
| [WOLFSSL] | wolfSSL/wolfCrypt cryptographic library | https://www.wolfssl.com/ |

---

*End of XEP-XQR draft, version 0.1.0.*
