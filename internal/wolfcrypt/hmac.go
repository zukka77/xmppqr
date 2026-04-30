package wolfcrypt

/*
#cgo pkg-config: wolfssl
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <stdlib.h>
*/
import "C"
import "unsafe"

func hmac(hashType C.int, key, msg []byte, outLen int) ([]byte, error) {
	h := (*C.Hmac)(C.calloc(1, C.sizeof_Hmac))
	if h == nil {
		return nil, wolfErr(-1)
	}
	defer C.free(unsafe.Pointer(h))
	if rc := C.wc_HmacInit(h, nil, -1); rc != 0 {
		return nil, wolfErr(rc)
	}
	defer C.wc_HmacFree(h)
	var kp *C.byte
	if len(key) > 0 {
		kp = (*C.byte)(unsafe.Pointer(&key[0]))
	}
	if rc := C.wc_HmacSetKey(h, hashType, kp, C.word32(len(key))); rc != 0 {
		return nil, wolfErr(rc)
	}
	if len(msg) > 0 {
		if rc := C.wc_HmacUpdate(h, (*C.byte)(unsafe.Pointer(&msg[0])), C.word32(len(msg))); rc != 0 {
			return nil, wolfErr(rc)
		}
	}
	out := make([]byte, outLen)
	if rc := C.wc_HmacFinal(h, (*C.byte)(unsafe.Pointer(&out[0]))); rc != 0 {
		return nil, wolfErr(rc)
	}
	return out, nil
}

func HMACSHA256(key, msg []byte) ([]byte, error) {
	return hmac(C.WC_SHA256, key, msg, 32)
}

func HMACSHA512(key, msg []byte) ([]byte, error) {
	return hmac(C.WC_SHA512, key, msg, 64)
}
