package wolfcrypt

/*
#cgo pkg-config: wolfssl
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <stdlib.h>
*/
import "C"
import "unsafe"

func GenerateEd25519() (pub, priv []byte, err error) {
	rngMu.Lock()
	defer rngMu.Unlock()
	r, err := getRNG()
	if err != nil {
		return nil, nil, err
	}
	key := (*C.ed25519_key)(C.calloc(1, C.sizeof_ed25519_key))
	if key == nil {
		return nil, nil, wolfErr(-1)
	}
	defer C.free(unsafe.Pointer(key))
	if rc := C.wc_ed25519_init(key); rc != 0 {
		return nil, nil, wolfErr(rc)
	}
	defer C.wc_ed25519_free(key)
	if rc := C.wc_ed25519_make_key(r, 32, key); rc != 0 {
		return nil, nil, wolfErr(rc)
	}
	pub = make([]byte, 32)
	priv = make([]byte, 64)
	pubSz := C.word32(32)
	privSz := C.word32(64)
	if rc := C.wc_ed25519_export_public(key, (*C.byte)(unsafe.Pointer(&pub[0])), &pubSz); rc != 0 {
		return nil, nil, wolfErr(rc)
	}
	if rc := C.wc_ed25519_export_private(key, (*C.byte)(unsafe.Pointer(&priv[0])), &privSz); rc != 0 {
		return nil, nil, wolfErr(rc)
	}
	return pub[:pubSz], priv[:privSz], nil
}

func Ed25519Sign(priv, msg []byte) ([]byte, error) {
	key := (*C.ed25519_key)(C.calloc(1, C.sizeof_ed25519_key))
	if key == nil {
		return nil, wolfErr(-1)
	}
	defer C.free(unsafe.Pointer(key))
	if rc := C.wc_ed25519_init(key); rc != 0 {
		return nil, wolfErr(rc)
	}
	defer C.wc_ed25519_free(key)
	if len(priv) == 64 {
		if rc := C.wc_ed25519_import_private_key(
			(*C.byte)(unsafe.Pointer(&priv[0])), 32,
			(*C.byte)(unsafe.Pointer(&priv[32])), 32,
			key); rc != 0 {
			return nil, wolfErr(rc)
		}
	} else {
		if rc := C.wc_ed25519_import_private_only((*C.byte)(unsafe.Pointer(&priv[0])), C.word32(len(priv)), key); rc != 0 {
			return nil, wolfErr(rc)
		}
	}
	sig := make([]byte, 64)
	sigSz := C.word32(64)
	if rc := C.wc_ed25519_sign_msg((*C.byte)(unsafe.Pointer(&msg[0])), C.word32(len(msg)), (*C.byte)(unsafe.Pointer(&sig[0])), &sigSz, key); rc != 0 {
		return nil, wolfErr(rc)
	}
	return sig[:sigSz], nil
}

func Ed25519Verify(pub, msg, sig []byte) (bool, error) {
	key := (*C.ed25519_key)(C.calloc(1, C.sizeof_ed25519_key))
	if key == nil {
		return false, wolfErr(-1)
	}
	defer C.free(unsafe.Pointer(key))
	if rc := C.wc_ed25519_init(key); rc != 0 {
		return false, wolfErr(rc)
	}
	defer C.wc_ed25519_free(key)
	if rc := C.wc_ed25519_import_public((*C.byte)(unsafe.Pointer(&pub[0])), C.word32(len(pub)), key); rc != 0 {
		return false, wolfErr(rc)
	}
	var res C.int
	rc := C.wc_ed25519_verify_msg((*C.byte)(unsafe.Pointer(&sig[0])), C.word32(len(sig)), (*C.byte)(unsafe.Pointer(&msg[0])), C.word32(len(msg)), &res, key)
	if rc != 0 {
		return false, nil
	}
	return res == 1, nil
}
