# XMPP Federation (S2S)

## What is federation?

XMPP federation, defined in RFC 6121 and implemented via the server-to-server (S2S) protocol
(RFC 7590 / XEP-0220), allows users on different XMPP domains to exchange messages. When
`alice@a.example` sends a message to `bob@b.example`, the `a.example` server opens an S2S
connection to `b.example` on TCP port 5269, authenticates via dialback, and delivers the stanza.

## Enabling federation in xmppqrd

Set `S2S.Enabled = true` in configuration and specify the listener address:

```yaml
s2s:
  enabled: true
  dialback_enabled: true
  insecure_skip_verify: false
  allowed_domains: []   # empty = accept any verified domain

listeners:
  s2s: ":5269"
```

The `S2SConfig` fields:

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Activate the S2S subsystem |
| `dialback_enabled` | `true` | Offer and require XEP-0220 dialback |
| `insecure_skip_verify` | `false` | Skip TLS certificate verification (testing only) |
| `allowed_domains` | `[]` | Allowlist of remote domains; empty = allow all verified |

## How dialback works (XEP-0220)

1. The initiating server opens a TCP connection and sends a stream header.
2. Both sides negotiate STARTTLS; the initiating server upgrades to TLS.
3. The initiating server sends `<db:result>` with a key computed as:

   ```
   HEX(HMAC-SHA-256(SHA-256(shared_secret), receiving + " " + originating + " " + stream_id))
   ```

4. The receiving server recomputes the key using its own copy of the dialback secret and responds
   `<db:result type='valid'/>` or `<db:result type='invalid'/>`.
5. After a `valid` response, the connection is authenticated and stanza delivery begins.

The dialback secret is generated randomly at startup and is not shared with remote servers; it is
used only for self-verification. Dialback proves domain ownership but does not replace TLS for
channel encryption.

## TLS and STARTTLS

xmppqrd requires STARTTLS before accepting dialback (`<starttls><required/></starttls>` in
stream features). The minimum TLS version is TLS 1.2, matching the C2S listener.

## Post-quantum TLS in federation

When connecting outbound, xmppqrd offers `X25519MLKEM768` (hybrid X25519 + ML-KEM-768) as the
preferred key-exchange group, with classical ECDHE groups as fallback. Receiving peers that do not
support PQ groups will negotiate classical TLS 1.3 automatically. This mirrors the C2S behaviour.

## Known limitations

- **SASL EXTERNAL / mTLS**: mutual TLS-based authentication (RFC 6120 §6.3.4) is not implemented.
  Planned for a future release. Dialback is the only supported authentication mechanism.
- **DANE / POSH**: DNS-based authentication of named entities (RFC 7673) and PKIX Over Secure HTTP
  (XEP-0156 variant) are not implemented. Certificate verification relies on the system trust store
  unless `insecure_skip_verify` is set.
- **Rate limiting**: There is no rate limit on inbound dialback verification attempts. Deployers
  should apply network-level controls if exposed to the public internet.
- **SRV-only discovery**: Remote server addresses are resolved via `_xmpp-server._tcp.<domain>` SRV
  DNS records. A fallback to `<domain>:5269` is used when no SRV record exists.

## Integration test seam

The `s2s.Pool.PinTarget(domain, addr string)` method overrides SRV resolution for a given domain.
The integration harness uses this to wire two in-process server instances together without DNS:

```go
aH.AddS2SPeer("b.test", bH.S2SAddr())
bH.AddS2SPeer("a.test", aH.S2SAddr())
```

`Pool.SetSkipTLS(true)` disables STARTTLS negotiation for tests that use in-process connections
and do not need a certificate on the S2S channel. Never use this in production.
