#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUBMODULE="$ROOT/deps/wolfssl"
PREFIX="${XMPPQR_WOLFSSL_PREFIX:-$ROOT/.local/wolfssl-v5.9.1}"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')}"

if [[ ! -d "$SUBMODULE/.git" && ! -f "$SUBMODULE/.git" ]]; then
    git -C "$ROOT" submodule update --init --checkout deps/wolfssl
fi

if [[ ! -x "$SUBMODULE/configure" ]]; then
    (cd "$SUBMODULE" && ./autogen.sh)
fi

mkdir -p "$PREFIX"

configure_args=(
    "--prefix=$PREFIX"
    "--disable-shared"
    "--enable-static"
    "--disable-examples"
    "--disable-crypttests"
    "--enable-opensslextra"
    "--enable-tlsx"
    "--enable-sni"
    "--enable-sessioncerts"
    "--enable-blake2"
    "--enable-hkdf"
    "--enable-aesgcm"
    "--enable-curve25519"
    "--enable-ed25519"
    "--enable-pwdbased"
    "--enable-scrypt"
    "--enable-keying-material"
    "--enable-kyber"
    "--enable-dilithium"
    "--enable-experimental"
)

(
    cd "$SUBMODULE"
    CFLAGS="${CFLAGS:-"-O2 -fPIC"}" ./configure "${configure_args[@]}"
    make -j"$JOBS"
    make install
)

lib="$PREFIX/lib/libwolfssl.a"
pc="$PREFIX/lib/pkgconfig/wolfssl.pc"
if [[ ! -f "$lib" ]]; then
    printf 'missing expected static library: %s\n' "$lib" >&2
    exit 1
fi
if [[ ! -f "$pc" ]]; then
    printf 'missing expected pkg-config file: %s\n' "$pc" >&2
    exit 1
fi

required_symbols=(
    wc_InitBlake2b
    wc_scrypt
    wc_dilithium_make_key
    wc_MlKemKey_New
    wolfSSL_export_keying_material
    wolfSSL_get_peer_chain
    wolfSSL_get_servername
    wolfSSL_CTX_set_min_proto_version
)

for symbol in "${required_symbols[@]}"; do
    if ! nm -g "$lib" | grep -Eq "[[:space:]]${symbol}$"; then
        printf 'local wolfSSL is missing required symbol: %s\n' "$symbol" >&2
        exit 1
    fi
done

printf 'local wolfSSL ready: %s\n' "$PREFIX"
