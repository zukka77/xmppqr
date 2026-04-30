# xmppqr

A new-generation Jabber/XMPP server with first-class post-quantum cryptography. All TLS and protocol-layer crypto goes through **wolfSSL/wolfCrypt**. Designed to replace ejabberd for medium-to-large deployments (10k+ concurrent users).

## License

**AGPLv3.** See [LICENSE](./LICENSE). Network-server copyleft is the right tool for a federated messaging server: any modified version that talks to users over the network must publish its source. wolfSSL (GPLv2-or-later) is compatible.

## Status

Pre-alpha. Build is not yet working end-to-end. See [docs/architecture.md](./docs/architecture.md) and the implementation plan in `~/.claude/plans/` for the design.

## Build prerequisites

- Go 1.26+
- wolfSSL 5.8+ built with at minimum: `--enable-tls13 --enable-mlkem --enable-curve25519 --enable-ed25519 --enable-hkdf --enable-aesgcm --enable-keylog-export`
- For ML-DSA (Phase 0.5): also `--enable-dilithium --enable-experimental`
- PostgreSQL 15+ for the production storage backend
