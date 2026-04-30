package wolfcrypt

/*
#cgo pkg-config: wolfssl
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/random.h>
#include <stdlib.h>
#include <string.h>

// wc_curve25519_set_rng is compiled in the system wolfSSL (WOLFSSL_CURVE25519_BLINDING)
// but not exposed in dev headers; declare it manually.
int wc_curve25519_set_rng(curve25519_key* key, WC_RNG* rng);

static int x25519_generate(WC_RNG* rng, unsigned char* pub, unsigned char* priv) {
    curve25519_key* key = (curve25519_key*)calloc(1, sizeof(curve25519_key));
    if (!key) return -1;
    wc_curve25519_init(key);
    int r = wc_curve25519_make_key(rng, 32, key);
    if (r == 0) {
        word32 sz = 32;
        r = wc_curve25519_export_public(key, pub, &sz);
    }
    if (r == 0) {
        word32 sz = 32;
        r = wc_curve25519_export_private_raw(key, priv, &sz);
    }
    wc_curve25519_free(key);
    free(key);
    return r;
}

static int x25519_shared(WC_RNG* rng, const unsigned char* priv, const unsigned char* peerPub, unsigned char* ss) {
    curve25519_key* privKey = (curve25519_key*)calloc(1, sizeof(curve25519_key));
    curve25519_key* pubKey  = (curve25519_key*)calloc(1, sizeof(curve25519_key));
    if (!privKey || !pubKey) { free(privKey); free(pubKey); return -1; }
    wc_curve25519_init(privKey);
    wc_curve25519_init(pubKey);
    // Set blinding RNG (required when WOLFSSL_CURVE25519_BLINDING is compiled in)
    wc_curve25519_set_rng(privKey, rng);
    int r = wc_curve25519_import_private(priv, 32, privKey);
    if (r == 0) r = wc_curve25519_import_public(peerPub, 32, pubKey);
    if (r == 0) {
        word32 ssSz = 32;
        r = wc_curve25519_shared_secret(privKey, pubKey, ss, &ssSz);
    }
    wc_curve25519_free(privKey);
    wc_curve25519_free(pubKey);
    free(privKey);
    free(pubKey);
    return r;
}
*/
import "C"
import "unsafe"

func GenerateX25519() (pub, priv []byte, err error) {
	rngMu.Lock()
	defer rngMu.Unlock()
	r, err := getRNG()
	if err != nil {
		return nil, nil, err
	}
	pub = make([]byte, 32)
	priv = make([]byte, 32)
	if rc := C.x25519_generate(r, (*C.uchar)(unsafe.Pointer(&pub[0])), (*C.uchar)(unsafe.Pointer(&priv[0]))); rc != 0 {
		return nil, nil, wolfErr(rc)
	}
	return pub, priv, nil
}

func X25519SharedSecret(priv, peerPub []byte) ([]byte, error) {
	rngMu.Lock()
	defer rngMu.Unlock()
	r, err := getRNG()
	if err != nil {
		return nil, err
	}
	ss := make([]byte, 32)
	rc := C.x25519_shared(
		r,
		(*C.uchar)(unsafe.Pointer(&priv[0])),
		(*C.uchar)(unsafe.Pointer(&peerPub[0])),
		(*C.uchar)(unsafe.Pointer(&ss[0])))
	if rc != 0 {
		return nil, wolfErr(rc)
	}
	return ss, nil
}
