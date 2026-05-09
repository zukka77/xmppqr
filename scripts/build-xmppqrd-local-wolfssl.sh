#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${XMPPQR_WOLFSSL_PREFIX:-$ROOT/.local/wolfssl-v5.9.1}"

if [[ ! -f "$PREFIX/lib/libwolfssl.a" || ! -f "$PREFIX/lib/pkgconfig/wolfssl.pc" ]]; then
    "$ROOT/scripts/build-local-wolfssl.sh"
fi

export PKG_CONFIG_LIBDIR="$PREFIX/lib/pkgconfig"
export CGO_LDFLAGS="${CGO_LDFLAGS:+$CGO_LDFLAGS }-lm"

cd "$ROOT"
go build -o ./xmppqrd ./cmd/xmppqrd
