package wolfcrypt

/*
#cgo pkg-config: wolfssl
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hmac.h>
*/
import "C"
import "unsafe"

func HKDFExtract(salt, ikm []byte) ([]byte, error) {
	out := make([]byte, 64)
	var saltp, ikmp *C.byte
	if len(salt) > 0 {
		saltp = (*C.byte)(unsafe.Pointer(&salt[0]))
	}
	if len(ikm) > 0 {
		ikmp = (*C.byte)(unsafe.Pointer(&ikm[0]))
	}
	rc := C.wc_HKDF_Extract(C.WC_SHA512, saltp, C.word32(len(salt)), ikmp, C.word32(len(ikm)), (*C.byte)(unsafe.Pointer(&out[0])))
	if rc != 0 {
		return nil, wolfErr(rc)
	}
	return out, nil
}

func HKDFExpand(prk, info []byte, n int) ([]byte, error) {
	out := make([]byte, n)
	var infop *C.byte
	if len(info) > 0 {
		infop = (*C.byte)(unsafe.Pointer(&info[0]))
	}
	rc := C.wc_HKDF_Expand(C.WC_SHA512, (*C.byte)(unsafe.Pointer(&prk[0])), C.word32(len(prk)), infop, C.word32(len(info)), (*C.byte)(unsafe.Pointer(&out[0])), C.word32(n))
	if rc != 0 {
		return nil, wolfErr(rc)
	}
	return out, nil
}
