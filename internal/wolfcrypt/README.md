# internal/wolfcrypt

cgo wrappers for wolfSSL/wolfCrypt primitives, targeted at wolfSSL **5.9.1** (system library on Debian).

## Primitives provided

| Primitive | Functions |
|---|---|
| ML-KEM-768 (FIPS 203) | `GenerateMLKEM768`, `MLKEM768Encapsulate`, `MLKEM768Decapsulate` |
| HKDF-SHA-512 | `HKDFExtract`, `HKDFExpand` |
| AES-256-GCM | `NewAESGCM`, `(*AESGCM).Seal`, `(*AESGCM).Open` |
| X25519 | `GenerateX25519`, `X25519SharedSecret` |
| Ed25519 | `GenerateEd25519`, `Ed25519Sign`, `Ed25519Verify` |
| HMAC-SHA-256/512 | `HMACSHA256`, `HMACSHA512` |
| SHA-256/512 | `SHA256`, `SHA512` |
| RNG | `Read` |

## Notes

- The system wolfSSL (5.9.1) is compiled with `WOLFSSL_CURVE25519_BLINDING` but the dev headers (`libwolfssl-dev`) do not expose this. `wc_curve25519_set_rng` is declared manually in `x25519.go` to work around the header/binary mismatch.

## TODO

ML-DSA-65 (`wc_dilithium_*`) requires rebuilding wolfSSL with `--enable-dilithium --enable-experimental` and is deferred; the system wolfSSL does not have it.
