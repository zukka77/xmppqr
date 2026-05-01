package wolfcrypt

/*
#cgo pkg-config: wolfssl
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
*/
import "C"
import "unsafe"

func GenerateMLKEM768() (pub, priv []byte, err error) {
	rngMu.Lock()
	defer rngMu.Unlock()
	r, err := getRNG()
	if err != nil {
		return nil, nil, err
	}
	key := C.wc_MlKemKey_New(C.WC_ML_KEM_768, nil, -1)
	if key == nil {
		return nil, nil, wolfErr(-1)
	}
	defer C.wc_MlKemKey_Delete(key, nil)
	if rc := C.wc_MlKemKey_MakeKey(key, r); rc != 0 {
		return nil, nil, wolfErr(rc)
	}
	var pubSz, privSz C.word32
	if rc := C.wc_MlKemKey_PublicKeySize(key, &pubSz); rc != 0 {
		return nil, nil, wolfErr(rc)
	}
	if rc := C.wc_MlKemKey_PrivateKeySize(key, &privSz); rc != 0 {
		return nil, nil, wolfErr(rc)
	}
	pub = make([]byte, pubSz)
	priv = make([]byte, privSz)
	if rc := C.wc_MlKemKey_EncodePublicKey(key, (*C.byte)(unsafe.Pointer(&pub[0])), pubSz); rc != 0 {
		return nil, nil, wolfErr(rc)
	}
	if rc := C.wc_MlKemKey_EncodePrivateKey(key, (*C.byte)(unsafe.Pointer(&priv[0])), privSz); rc != 0 {
		return nil, nil, wolfErr(rc)
	}
	return pub, priv, nil
}

func MLKEM768Encapsulate(pub []byte) (ct, ss []byte, err error) {
	rngMu.Lock()
	defer rngMu.Unlock()
	r, err := getRNG()
	if err != nil {
		return nil, nil, err
	}
	key := C.wc_MlKemKey_New(C.WC_ML_KEM_768, nil, -1)
	if key == nil {
		return nil, nil, wolfErr(-1)
	}
	defer C.wc_MlKemKey_Delete(key, nil)
	if rc := C.wc_MlKemKey_DecodePublicKey(key, (*C.byte)(unsafe.Pointer(&pub[0])), C.word32(len(pub))); rc != 0 {
		return nil, nil, wolfErr(rc)
	}
	var ctSz, ssSz C.word32
	if rc := C.wc_MlKemKey_CipherTextSize(key, &ctSz); rc != 0 {
		return nil, nil, wolfErr(rc)
	}
	if rc := C.wc_MlKemKey_SharedSecretSize(key, &ssSz); rc != 0 {
		return nil, nil, wolfErr(rc)
	}
	ct = make([]byte, ctSz)
	ss = make([]byte, ssSz)
	if rc := C.wc_MlKemKey_Encapsulate(key, (*C.byte)(unsafe.Pointer(&ct[0])), (*C.byte)(unsafe.Pointer(&ss[0])), r); rc != 0 {
		return nil, nil, wolfErr(rc)
	}
	return ct, ss, nil
}

func MLKEM768Decapsulate(priv, ct []byte) (ss []byte, err error) {
	key := C.wc_MlKemKey_New(C.WC_ML_KEM_768, nil, -1)
	if key == nil {
		return nil, wolfErr(-1)
	}
	defer C.wc_MlKemKey_Delete(key, nil)
	if rc := C.wc_MlKemKey_DecodePrivateKey(key, (*C.byte)(unsafe.Pointer(&priv[0])), C.word32(len(priv))); rc != 0 {
		return nil, wolfErr(rc)
	}
	var ssSz C.word32
	if rc := C.wc_MlKemKey_SharedSecretSize(key, &ssSz); rc != 0 {
		return nil, wolfErr(rc)
	}
	ss = make([]byte, ssSz)
	if rc := C.wc_MlKemKey_Decapsulate(key, (*C.byte)(unsafe.Pointer(&ss[0])), (*C.byte)(unsafe.Pointer(&ct[0])), C.word32(len(ct))); rc != 0 {
		return nil, wolfErr(rc)
	}
	return ss, nil
}
