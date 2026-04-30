package wolfcrypt

/*
#cgo pkg-config: wolfssl
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"unsafe"
)

type AESGCM struct {
	key []byte
}

func NewAESGCM(key []byte) (*AESGCM, error) {
	if len(key) != 32 {
		return nil, errors.New("aesgcm: key must be 32 bytes")
	}
	k := make([]byte, 32)
	copy(k, key)
	return &AESGCM{key: k}, nil
}

func (a *AESGCM) Seal(nonce, plaintext, aad []byte) ([]byte, error) {
	if len(nonce) != 12 {
		return nil, errors.New("aesgcm: nonce must be 12 bytes")
	}
	aes := (*C.Aes)(C.calloc(1, C.sizeof_Aes))
	if aes == nil {
		return nil, wolfErr(-1)
	}
	defer C.free(unsafe.Pointer(aes))
	if rc := C.wc_AesInit(aes, nil, -1); rc != 0 {
		return nil, wolfErr(rc)
	}
	defer C.wc_AesFree(aes)
	if rc := C.wc_AesGcmSetKey(aes, (*C.byte)(unsafe.Pointer(&a.key[0])), C.word32(len(a.key))); rc != 0 {
		return nil, wolfErr(rc)
	}
	ct := make([]byte, len(plaintext)+16)
	var inp *C.byte
	if len(plaintext) > 0 {
		inp = (*C.byte)(unsafe.Pointer(&plaintext[0]))
	}
	var aadp *C.byte
	if len(aad) > 0 {
		aadp = (*C.byte)(unsafe.Pointer(&aad[0]))
	}
	rc := C.wc_AesGcmEncrypt(aes,
		(*C.byte)(unsafe.Pointer(&ct[0])),
		inp, C.word32(len(plaintext)),
		(*C.byte)(unsafe.Pointer(&nonce[0])), 12,
		(*C.byte)(unsafe.Pointer(&ct[len(plaintext)])), 16,
		aadp, C.word32(len(aad)))
	if rc != 0 {
		return nil, wolfErr(rc)
	}
	return ct, nil
}

func (a *AESGCM) Open(nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != 12 {
		return nil, errors.New("aesgcm: nonce must be 12 bytes")
	}
	if len(ciphertext) < 16 {
		return nil, errors.New("aesgcm: ciphertext too short")
	}
	aes := (*C.Aes)(C.calloc(1, C.sizeof_Aes))
	if aes == nil {
		return nil, wolfErr(-1)
	}
	defer C.free(unsafe.Pointer(aes))
	if rc := C.wc_AesInit(aes, nil, -1); rc != 0 {
		return nil, wolfErr(rc)
	}
	defer C.wc_AesFree(aes)
	if rc := C.wc_AesGcmSetKey(aes, (*C.byte)(unsafe.Pointer(&a.key[0])), C.word32(len(a.key))); rc != 0 {
		return nil, wolfErr(rc)
	}
	msgLen := len(ciphertext) - 16
	pt := make([]byte, msgLen)
	var outp *C.byte
	var inp *C.byte
	if msgLen > 0 {
		outp = (*C.byte)(unsafe.Pointer(&pt[0]))
		inp = (*C.byte)(unsafe.Pointer(&ciphertext[0]))
	}
	var aadp *C.byte
	if len(aad) > 0 {
		aadp = (*C.byte)(unsafe.Pointer(&aad[0]))
	}
	rc := C.wc_AesGcmDecrypt(aes,
		outp,
		inp, C.word32(msgLen),
		(*C.byte)(unsafe.Pointer(&nonce[0])), 12,
		(*C.byte)(unsafe.Pointer(&ciphertext[msgLen])), 16,
		aadp, C.word32(len(aad)))
	if rc != 0 {
		return nil, wolfErr(rc)
	}
	return pt, nil
}
