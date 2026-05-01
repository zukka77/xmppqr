// SPDX-License-Identifier: AGPL-3.0-or-later
package wolfcrypt

/*
#cgo pkg-config: wolfssl
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <stdlib.h>

static int dilithium_new_key(dilithium_key **out) {
    dilithium_key *key = (dilithium_key *)calloc(1, sizeof(dilithium_key));
    if (key == NULL) return -1;
    int ret = wc_dilithium_init(key);
    if (ret != 0) { free(key); return ret; }
    ret = wc_dilithium_set_level(key, 3);
    if (ret != 0) { wc_dilithium_free(key); free(key); return ret; }
    *out = key;
    return 0;
}

static void dilithium_destroy_key(dilithium_key *key) {
    if (key != NULL) {
        wc_dilithium_free(key);
        free(key);
    }
}
*/
import "C"
import "unsafe"

const (
	MLDSA65PubSize  = 1952
	MLDSA65PrivSize = 5984 // raw priv (4032) || pub (1952) — split on import
	MLDSA65SigSize  = 3309

	mldsa65RawPrivSize = 4032
)

func GenerateMLDSA65() (pub, priv []byte, err error) {
	rngMu.Lock()
	defer rngMu.Unlock()
	r, err := getRNG()
	if err != nil {
		return nil, nil, err
	}
	var key *C.dilithium_key
	if rc := C.dilithium_new_key(&key); rc != 0 {
		return nil, nil, wolfErr(rc)
	}
	defer C.dilithium_destroy_key(key)

	if rc := C.wc_dilithium_make_key(key, r); rc != 0 {
		return nil, nil, wolfErr(rc)
	}

	pub = make([]byte, MLDSA65PubSize)
	pubSz := C.word32(MLDSA65PubSize)
	if rc := C.wc_dilithium_export_public(key, (*C.byte)(unsafe.Pointer(&pub[0])), &pubSz); rc != 0 {
		return nil, nil, wolfErr(rc)
	}
	pub = pub[:pubSz]

	rawPriv := make([]byte, mldsa65RawPrivSize)
	rawPrivSz := C.word32(mldsa65RawPrivSize)
	if rc := C.wc_dilithium_export_private(key, (*C.byte)(unsafe.Pointer(&rawPriv[0])), &rawPrivSz); rc != 0 {
		return nil, nil, wolfErr(rc)
	}
	priv = append(rawPriv[:rawPrivSz], pub...)

	return pub, priv, nil
}

func MLDSA65Sign(priv, msg []byte) (sig []byte, err error) {
	rngMu.Lock()
	defer rngMu.Unlock()
	r, err := getRNG()
	if err != nil {
		return nil, err
	}
	var key *C.dilithium_key
	if rc := C.dilithium_new_key(&key); rc != 0 {
		return nil, wolfErr(rc)
	}
	defer C.dilithium_destroy_key(key)

	rawPriv := priv[:mldsa65RawPrivSize]
	embPub := priv[mldsa65RawPrivSize:]
	if rc := C.wc_dilithium_import_key(
		(*C.byte)(unsafe.Pointer(&rawPriv[0])), C.word32(len(rawPriv)),
		(*C.byte)(unsafe.Pointer(&embPub[0])), C.word32(len(embPub)),
		key); rc != 0 {
		return nil, wolfErr(rc)
	}

	sig = make([]byte, MLDSA65SigSize)
	sigSz := C.word32(MLDSA65SigSize)
	rc := C.wc_dilithium_sign_ctx_msg(
		nil, 0,
		(*C.byte)(unsafe.Pointer(&msg[0])), C.word32(len(msg)),
		(*C.byte)(unsafe.Pointer(&sig[0])), &sigSz,
		key, r)
	if rc != 0 {
		return nil, wolfErr(rc)
	}
	return sig[:sigSz], nil
}

func MLDSA65Verify(pub, msg, sig []byte) (ok bool, err error) {
	var key *C.dilithium_key
	if rc := C.dilithium_new_key(&key); rc != 0 {
		return false, wolfErr(rc)
	}
	defer C.dilithium_destroy_key(key)

	if rc := C.wc_dilithium_import_public((*C.byte)(unsafe.Pointer(&pub[0])), C.word32(len(pub)), key); rc != 0 {
		return false, wolfErr(rc)
	}

	var res C.int
	rc := C.wc_dilithium_verify_ctx_msg(
		(*C.byte)(unsafe.Pointer(&sig[0])), C.word32(len(sig)),
		nil, 0,
		(*C.byte)(unsafe.Pointer(&msg[0])), C.word32(len(msg)),
		&res, key)
	if rc != 0 {
		return false, nil
	}
	return res == 1, nil
}
